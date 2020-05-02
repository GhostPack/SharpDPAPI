using System;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.ComponentModel;
using System.IO;

namespace SharpDPAPI
{
    public class Crypto
    {
        public static string KerberosPasswordHash(Interop.KERB_ETYPE etype, string password, string salt = "", int count = 4096)
        {
            // use the internal KERB_ECRYPT HashPassword() function to calculate a password hash of a given etype
            // adapted from @gentilkiwi's Mimikatz "kerberos::hash" implementation

            Interop.KERB_ECRYPT pCSystem;
            IntPtr pCSystemPtr;

            // locate the crypto system for the hash type we want
            int status = Interop.CDLocateCSystem(etype, out pCSystemPtr);

            pCSystem = (Interop.KERB_ECRYPT)System.Runtime.InteropServices.Marshal.PtrToStructure(pCSystemPtr, typeof(Interop.KERB_ECRYPT));
            if (status != 0)
                throw new System.ComponentModel.Win32Exception(status, "Error on CDLocateCSystem");

            // get the delegate for the password hash function
            Interop.KERB_ECRYPT_HashPassword pCSystemHashPassword = (Interop.KERB_ECRYPT_HashPassword)System.Runtime.InteropServices.Marshal.GetDelegateForFunctionPointer(pCSystem.HashPassword, typeof(Interop.KERB_ECRYPT_HashPassword));
            Interop.UNICODE_STRING passwordUnicode = new Interop.UNICODE_STRING(password);
            Interop.UNICODE_STRING saltUnicode = new Interop.UNICODE_STRING(salt);

            byte[] output = new byte[pCSystem.KeySize];

            int success = pCSystemHashPassword(passwordUnicode, saltUnicode, count, output);

            if (status != 0)
                throw new Win32Exception(status);

            return System.BitConverter.ToString(output).Replace("-", "");
        }
        
        public static byte[] DecryptBlob(byte[] ciphertext, byte[] key, int algCrypt = 26115, PaddingMode padding = PaddingMode.Zeros)
        {
            // decrypts a DPAPI blob using 3DES or AES

            // reference: https://docs.microsoft.com/en-us/windows/desktop/seccrypto/alg-id
            // 26115 == CALG_3DES
            // 26128 == CALG_AES_256

            if (algCrypt == 26115)
            {
                // takes a byte array of ciphertext bytes and a key array, decrypt the blob with 3DES
                TripleDESCryptoServiceProvider desCryptoProvider = new TripleDESCryptoServiceProvider();

                byte[] ivBytes = new byte[8];

                desCryptoProvider.Key = key;
                desCryptoProvider.IV = ivBytes;
                desCryptoProvider.Mode = CipherMode.CBC;
                desCryptoProvider.Padding = padding;
                try
                {
                    byte[] plaintextBytes = desCryptoProvider.CreateDecryptor()
                        .TransformFinalBlock(ciphertext, 0, ciphertext.Length);
                    return plaintextBytes;
                }
                catch (Exception e)
                {
                    Console.WriteLine("[x] An exception occured: {0}", e);
                }

                return new byte[0];
            }
            else if (algCrypt == 26128)
            {
                // takes a byte array of ciphertext bytes and a key array, decrypt the blob with AES256
                AesManaged aesCryptoProvider = new AesManaged();

                byte[] ivBytes = new byte[16];

                aesCryptoProvider.Key = key;
                aesCryptoProvider.IV = ivBytes;
                aesCryptoProvider.Mode = CipherMode.CBC;
                aesCryptoProvider.Padding = padding;

                byte[] plaintextBytes = aesCryptoProvider.CreateDecryptor().TransformFinalBlock(ciphertext, 0, ciphertext.Length);

                return plaintextBytes;
            }
            else
            {
                return new byte[0];
            }
        }

        public static byte[] DeriveKey(byte[] keyBytes, byte[] saltBytes, int algHash = 32772)
        {
            // derives a dpapi session key using Microsoft crypto "magic"

            // calculate the session key -> HMAC(salt) where the sha1(masterkey) is the key

            if (algHash == 32782)
            {
                // 32782 == CALG_SHA_512
                HMACSHA512 hmac = new HMACSHA512(keyBytes);
                byte[] sessionKeyBytes = hmac.ComputeHash(saltBytes);
                return sessionKeyBytes;
            }

            else if (algHash == 32772)
            {
                // 32772 == CALG_SHA1

                HMACSHA1 hmac = new HMACSHA1(keyBytes);
                
                byte[] ipad = new byte[64];
                byte[] opad = new byte[64];

                byte[] sessionKeyBytes = hmac.ComputeHash(saltBytes);

                // "...wut" - anyone reading Microsoft crypto
                for (int i = 0; i < 64; i++)
                {
                    ipad[i] = Convert.ToByte('6');
                    opad[i] = Convert.ToByte('\\');
                }

                for (int i = 0; i < keyBytes.Length; i++)
                {
                    ipad[i] ^= sessionKeyBytes[i];
                    opad[i] ^= sessionKeyBytes[i];
                }

                using (SHA1Managed sha1 = new SHA1Managed())
                {
                    byte[] ipadSHA1bytes = sha1.ComputeHash(ipad);
                    byte[] opadSHA1bytes = sha1.ComputeHash(opad);

                    byte[] combined = Helpers.Combine(ipadSHA1bytes, opadSHA1bytes);
                    return combined;
                }
            }
            else
            {
                return new byte[0];
            }
        }
        public static string ExportPrivateKey(RSACryptoServiceProvider csp)
        {
            //https://stackoverflow.com/questions/23734792/c-sharp-export-private-public-rsa-key-from-rsacryptoserviceprovider-to-pem-strin
            StringWriter outputStream = new StringWriter();
            if (csp.PublicOnly) throw new ArgumentException("CSP does not contain a private key", "csp");
            var parameters = csp.ExportParameters(true);
            using (var stream = new MemoryStream())
            {
                var writer = new BinaryWriter(stream);
                writer.Write((byte)0x30); // Sequence
                using (var innerStream = new MemoryStream())
                {
                    var innerWriter = new BinaryWriter(innerStream);
                    Helpers.EncodeIntegerBigEndian(innerWriter, new byte[] { 0x00 }); // Version
                    Helpers.EncodeIntegerBigEndian(innerWriter, parameters.Modulus);
                    Helpers.EncodeIntegerBigEndian(innerWriter, parameters.Exponent);
                    Helpers.EncodeIntegerBigEndian(innerWriter, parameters.D);
                    Helpers.EncodeIntegerBigEndian(innerWriter, parameters.P);
                    Helpers.EncodeIntegerBigEndian(innerWriter, parameters.Q);
                    Helpers.EncodeIntegerBigEndian(innerWriter, parameters.DP);
                    Helpers.EncodeIntegerBigEndian(innerWriter, parameters.DQ);
                    Helpers.EncodeIntegerBigEndian(innerWriter, parameters.InverseQ);
                    var length = (int)innerStream.Length;
                    Helpers.EncodeLength(writer, length);
                    writer.Write(innerStream.GetBuffer(), 0, length);
                }

                var base64 = Convert.ToBase64String(stream.GetBuffer(), 0, (int)stream.Length).ToCharArray();

                outputStream.Write("-----BEGIN RSA PRIVATE KEY-----\n");

                for (var i = 0; i < base64.Length; i += 64)
                {
                    outputStream.Write(base64, i, Math.Min(64, base64.Length - i));
                    outputStream.Write("\n");
                }
                outputStream.Write("-----END RSA PRIVATE KEY-----");
            }

            return outputStream.ToString();
        }

        public static byte[] AESDecrypt(byte[] key, byte[] IV, byte[] data)
        {
            // helper to AES decrypt a given blob with optional IV

            AesManaged aesCryptoProvider = new AesManaged();

            aesCryptoProvider.Key = key;
            if (IV.Length != 0)
            {
                aesCryptoProvider.IV = IV;
            }
            aesCryptoProvider.Mode = CipherMode.CBC;

            byte[] plaintextBytes = aesCryptoProvider.CreateDecryptor().TransformFinalBlock(data, 0, data.Length);

            return plaintextBytes;
        }

        public static byte[] LSAAESDecrypt(byte[] key, byte[] data)
        {
            AesManaged aesCryptoProvider = new AesManaged();
            
            aesCryptoProvider.Key = key;
            aesCryptoProvider.IV = new byte[16];
            aesCryptoProvider.Mode = CipherMode.CBC;
            aesCryptoProvider.BlockSize = 128;
            aesCryptoProvider.Padding = PaddingMode.Zeros;
            ICryptoTransform transform = aesCryptoProvider.CreateDecryptor();

            int chunks = Decimal.ToInt32(Math.Ceiling((decimal)data.Length / (decimal)16));
            byte[] plaintext = new byte[chunks * 16];

            for (int i = 0; i < chunks; ++i)
            {
                int offset = i * 16;
                byte[] chunk = new byte[16];
                Array.Copy(data, offset, chunk, 0, 16);

                byte[] chunkPlaintextBytes = transform.TransformFinalBlock(chunk, 0, chunk.Length);
                Array.Copy(chunkPlaintextBytes, 0, plaintext, i * 16, 16);
            }
            
            return plaintext;
        }

        public static byte[] RSADecrypt(byte[] privateKey, byte[] dataToDecrypt)
        {
            // helper to RSA decrypt a given blob

            // PROV_RSA_AES == 24
            var cspParameters = new System.Security.Cryptography.CspParameters(24);

            using (var rsaProvider = new System.Security.Cryptography.RSACryptoServiceProvider(cspParameters))
            {
                try
                {
                    rsaProvider.PersistKeyInCsp = false;
                    rsaProvider.ImportCspBlob(privateKey);

                    byte[] dataToDecryptRev = new byte[256];

                    Buffer.BlockCopy(dataToDecrypt, 0, dataToDecryptRev, 0, dataToDecrypt.Length); // ... Array.Copy? naw... :(

                    Array.Reverse(dataToDecryptRev); // ... don't ask me how long it took to realize this :(

                    byte[] dec = rsaProvider.Decrypt(dataToDecryptRev, false); // no padding
                    return dec;
                }
                catch (Exception e)
                {
                    Console.WriteLine("Error decryption domain key: {0}", e.Message);
                }
                finally
                {
                    rsaProvider.PersistKeyInCsp = false;
                    rsaProvider.Clear();
                }
            }

            return new byte[0];
        }

        public static byte[] LSASHA256Hash(byte[]key, byte[] rawData)
        {
            // yay
            using (SHA256 sha256Hash = SHA256.Create())
            {
                byte[] buffer = new byte[key.Length + (rawData.Length * 1000)];
                Array.Copy(key, 0, buffer, 0, key.Length);
                for (int i = 0; i < 1000; ++i)
                {
                    Array.Copy(rawData, 0, buffer, key.Length + (i * rawData.Length), rawData.Length);
                }
                return sha256Hash.ComputeHash(buffer);
            }
        }
    }
}