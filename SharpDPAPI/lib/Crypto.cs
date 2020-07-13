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
            var status = Interop.CDLocateCSystem(etype, out pCSystemPtr);

            pCSystem = (Interop.KERB_ECRYPT)Marshal.PtrToStructure(pCSystemPtr, typeof(Interop.KERB_ECRYPT));
            if (status != 0)
                throw new Win32Exception(status, "Error on CDLocateCSystem");

            // get the delegate for the password hash function
            var pCSystemHashPassword = (Interop.KERB_ECRYPT_HashPassword)Marshal.GetDelegateForFunctionPointer(pCSystem.HashPassword, typeof(Interop.KERB_ECRYPT_HashPassword));
            var passwordUnicode = new Interop.UNICODE_STRING(password);
            var saltUnicode = new Interop.UNICODE_STRING(salt);

            var output = new byte[pCSystem.KeySize];

            status = pCSystemHashPassword(passwordUnicode, saltUnicode, count, output);

            if (status != 0)
                throw new Win32Exception(status);

            return BitConverter.ToString(output).Replace("-", "");
        }

        public static byte[] DecryptBlob(byte[] ciphertext, byte[] key, int algCrypt, PaddingMode padding = PaddingMode.Zeros)
        {
            // decrypts a DPAPI blob using 3DES or AES

            // reference: https://docs.microsoft.com/en-us/windows/desktop/seccrypto/alg-id


            switch (algCrypt)
            {
                case 26115: // 26115 == CALG_3DES
                {
                    // takes a byte array of ciphertext bytes and a key array, decrypt the blob with 3DES
                    var desCryptoProvider = new TripleDESCryptoServiceProvider();

                    var ivBytes = new byte[8];

                    desCryptoProvider.Key = key;
                    desCryptoProvider.IV = ivBytes;
                    desCryptoProvider.Mode = CipherMode.CBC;
                    desCryptoProvider.Padding = padding;
                    try
                    {
                        var plaintextBytes = desCryptoProvider.CreateDecryptor()
                            .TransformFinalBlock(ciphertext, 0, ciphertext.Length);
                        return plaintextBytes;
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine("[x] An exception occured: {0}", e);
                    }

                    return new byte[0];
                }

                case 26128: // 26128 == CALG_AES_256
                {
                    // takes a byte array of ciphertext bytes and a key array, decrypt the blob with AES256
                    var aesCryptoProvider = new AesManaged();

                    var ivBytes = new byte[16];

                    aesCryptoProvider.Key = key;
                    aesCryptoProvider.IV = ivBytes;
                    aesCryptoProvider.Mode = CipherMode.CBC;
                    aesCryptoProvider.Padding = padding;

                    var plaintextBytes = aesCryptoProvider.CreateDecryptor()
                        .TransformFinalBlock(ciphertext, 0, ciphertext.Length);

                    return plaintextBytes;
                }

                default:
                    throw new Exception($"Could not decrypt blob. Unsupported algorithm: {algCrypt}");
            }
        }

        public static byte[] DeriveKey(byte[] keyBytes, byte[] saltBytes, int algHash)
        {
            // derives a dpapi session key using Microsoft crypto "magic"

            // calculate the session key -> HMAC(salt) where the sha1(masterkey) is the key

            if (algHash == 32782)
            {
                // 32782 == CALG_SHA_512
                return HMACSha512(keyBytes, saltBytes);
            } else if (algHash == 32772)
            {
                // 32772 == CALG_SHA1

                var hmac = new HMACSHA1(keyBytes);
                var sessionKeyBytes = hmac.ComputeHash(saltBytes);


                var ipad = new byte[64];
                var opad = new byte[64];


                // "...wut" - anyone reading Microsoft crypto
                for (var i = 0; i < 64; i++)
                {
                    ipad[i] = Convert.ToByte('6');
                    opad[i] = Convert.ToByte('\\');
                }

                for (var i = 0; i < keyBytes.Length; i++)
                {
                    ipad[i] ^= sessionKeyBytes[i];
                    opad[i] ^= sessionKeyBytes[i];
                }

                using (var sha1 = new SHA1Managed())
                {
                    var ipadSHA1bytes = sha1.ComputeHash(ipad);
                    var opadSHA1bytes = sha1.ComputeHash(opad);

                    var combined = Helpers.Combine(ipadSHA1bytes, opadSHA1bytes);
                    return combined;
                }
            }
            else
            {
                return new byte[0];
            }
        }

        private static byte[] HMACSha512(byte[] keyBytes, byte[] saltBytes)
        {
            var hmac = new HMACSHA512(keyBytes);
            var sessionKeyBytes = hmac.ComputeHash(saltBytes);
            return sessionKeyBytes;
        }

        public static string ExportPrivateKey(RSACryptoServiceProvider csp)
        {
            //https://stackoverflow.com/questions/23734792/c-sharp-export-private-public-rsa-key-from-rsacryptoserviceprovider-to-pem-strin
            var outputStream = new StringWriter();
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

            var aesCryptoProvider = new AesManaged();

            aesCryptoProvider.Key = key;
            if (IV.Length != 0)
            {
                aesCryptoProvider.IV = IV;
            }
            aesCryptoProvider.Mode = CipherMode.CBC;

            var plaintextBytes = aesCryptoProvider.CreateDecryptor().TransformFinalBlock(data, 0, data.Length);

            return plaintextBytes;
        }

        public static byte[] LSAAESDecrypt(byte[] key, byte[] data)
        {
            var aesCryptoProvider = new AesManaged();
            
            aesCryptoProvider.Key = key;
            aesCryptoProvider.IV = new byte[16];
            aesCryptoProvider.Mode = CipherMode.CBC;
            aesCryptoProvider.BlockSize = 128;
            aesCryptoProvider.Padding = PaddingMode.Zeros;
            var transform = aesCryptoProvider.CreateDecryptor();

            var chunks = Decimal.ToInt32(Math.Ceiling((decimal)data.Length / (decimal)16));
            var plaintext = new byte[chunks * 16];

            for (var i = 0; i < chunks; ++i)
            {
                var offset = i * 16;
                var chunk = new byte[16];
                Array.Copy(data, offset, chunk, 0, 16);

                var chunkPlaintextBytes = transform.TransformFinalBlock(chunk, 0, chunk.Length);
                Array.Copy(chunkPlaintextBytes, 0, plaintext, i * 16, 16);
            }
            
            return plaintext;
        }

        public static byte[] RSADecrypt(byte[] privateKey, byte[] dataToDecrypt)
        {
            // helper to RSA decrypt a given blob

            // PROV_RSA_AES == 24
            var cspParameters = new CspParameters(24);

            using (var rsaProvider = new RSACryptoServiceProvider(cspParameters))
            {
                try
                {
                    rsaProvider.PersistKeyInCsp = false;
                    rsaProvider.ImportCspBlob(privateKey);

                    var dataToDecryptRev = new byte[256];

                    Buffer.BlockCopy(dataToDecrypt, 0, dataToDecryptRev, 0, dataToDecrypt.Length); // ... Array.Copy? naw... :(

                    Array.Reverse(dataToDecryptRev); // ... don't ask me how long it took to realize this :(

                    var dec = rsaProvider.Decrypt(dataToDecryptRev, false); // no padding
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
            using (var sha256Hash = SHA256.Create())
            {
                var buffer = new byte[key.Length + (rawData.Length * 1000)];
                Array.Copy(key, 0, buffer, 0, key.Length);
                for (var i = 0; i < 1000; ++i)
                {
                    Array.Copy(rawData, 0, buffer, key.Length + (i * rawData.Length), rawData.Length);
                }
                return sha256Hash.ComputeHash(buffer);
            }
        }
    }
}