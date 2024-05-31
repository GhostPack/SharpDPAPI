using System;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.ComponentModel;
using System.IO;
using System.Collections.Generic;

namespace SharpDPAPI
{
    public class Crypto
    {
        public enum EncryptionAlgorithm
        {
            CALG_3DES = 26115,
            CALG_AES_256 = 26128
        }

        public enum HashAlgorithm
        {
            CALG_SHA1 = 32772,
            CALG_SHA_256 = 32780,
            CALG_SHA_512 = 32782
        }

        public static byte[] GetRandomBytes(int length)
        {
            using (var rng = new RNGCryptoServiceProvider())
            {
                var randomBytes = new byte[length];
                rng.GetBytes(randomBytes);
                return randomBytes;
            }
        }

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

        public static byte[] EncryptBlob(byte[] plaintext, byte[] key, 
            EncryptionAlgorithm algCrypt, PaddingMode padding = PaddingMode.Zeros)
        {
            // encrypts a DPAPI blob using 3DES or AES

            switch (algCrypt)
            {
                case EncryptionAlgorithm.CALG_3DES:
                    {
                        // takes a byte array of plaintext bytes and a key array, encrypt the blob with 3DES
                        var desCryptoProvider = new TripleDESCryptoServiceProvider();

                        var ivBytes = new byte[8];

                        desCryptoProvider.Key = key;
                        desCryptoProvider.IV = ivBytes;
                        desCryptoProvider.Mode = CipherMode.CBC;
                        desCryptoProvider.Padding = padding;
                        try
                        {
                            var ciphertextBytes = desCryptoProvider.CreateEncryptor()
                                .TransformFinalBlock(plaintext, 0, plaintext.Length);
                            return ciphertextBytes;
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine("[x] An exception occured: {0}", e);
                        }

                        return new byte[0];
                    }

                case EncryptionAlgorithm.CALG_AES_256:
                    {
                        // takes a byte array of plaintext bytes and a key array, encrypt the blob with AES256
                        var aesCryptoProvider = new AesManaged();

                        var ivBytes = new byte[16];

                        aesCryptoProvider.Key = key;
                        aesCryptoProvider.IV = ivBytes;
                        aesCryptoProvider.Mode = CipherMode.CBC;
                        aesCryptoProvider.Padding = padding;

                        var ciphertextBytes = aesCryptoProvider.CreateEncryptor()
                            .TransformFinalBlock(plaintext, 0, plaintext.Length);

                        return ciphertextBytes;
                    }

                default:
                    throw new Exception($"Could not encrypt blob. Unsupported algorithm: {algCrypt}");
            }
        }

        public static byte[] DecryptBlob(byte[] ciphertext, byte[] key, int algCrypt, PaddingMode padding = PaddingMode.Zeros)
        {
            // decrypts a DPAPI blob using 3DES or AES

            // reference: https://docs.microsoft.com/en-us/windows/desktop/seccrypto/alg-id

            switch ((EncryptionAlgorithm)algCrypt)
            {
                case EncryptionAlgorithm.CALG_3DES:
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

                case EncryptionAlgorithm.CALG_AES_256:
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
        /*
def CryptSessionKeyWin7(masterkey, nonce, hashAlgo, entropy=None, strongPassword=None):
    """Computes the decryption key for XP DPAPI blob, given the masterkey and optional information.

    This implementation relies on an RFC compliant HMAC implementation
    This algorithm is also used when checking the HMAC for integrity after decryption

    :param masterkey: decrypted masterkey (should be 64 bytes long)
    :param nonce: this is the nonce contained in the blob or the HMAC in the blob (integrity check)
    :param entropy: this is the optional entropy from CryptProtectData() API
    :param strongPassword: optional password used for decryption or the blob itself (integrity check)
    :returns: decryption key
    :rtype : str
    """
    if len(masterkey) > 20:
        masterkey = hashlib.sha1(masterkey).digest()

    digest = M2Crypto.EVP.HMAC(masterkey, hashAlgo.name)
    digest.update(nonce)
    if entropy is not None:
        digest.update(entropy)
    if strongPassword is not None:
        digest.update(strongPassword)
    return digest.final()
        */

        public static byte[] DeriveKey(byte[] key, byte[] nonce, int hashAlgorithm, byte[] blob, byte[] entropy = null)
        {
            HMAC hmac;
            switch (hashAlgorithm)
            {
                case (int)HashAlgorithm.CALG_SHA1:
                    hmac = new HMACSHA1(key);
                    break;
                case (int)HashAlgorithm.CALG_SHA_256:
                    hmac = new HMACSHA256(key);
                    break;
                case (int)HashAlgorithm.CALG_SHA_512:
                    hmac = new HMACSHA512(key);
                    break;
                default:
                    throw new Exception($"Unsupported hash algorithm: {hashAlgorithm}");
            }

            var keyMaterial = new List<byte>();
            keyMaterial.AddRange(nonce);
            if (entropy != null)
            {
                keyMaterial.AddRange(entropy);
            }
            keyMaterial.AddRange(blob);

            return hmac.ComputeHash(keyMaterial.ToArray());
        }

        /*
        def CryptDeriveKey(h, cipherAlgo, hashAlgo):
            """Internal use. Mimics the corresponding native Microsoft function"""
            if len(h) > hashAlgo.blockSize:
                h = hashlib.new(hashAlgo.name, h).digest()
            if len(h) >= cipherAlgo.keyLength:
                return h
            h += "\x00" * hashAlgo.blockSize
            ipad = "".join(chr(ord(h[i]) ^ 0x36) for i in range(hashAlgo.blockSize))
            opad = "".join(chr(ord(h[i]) ^ 0x5c) for i in range(hashAlgo.blockSize))
            k = hashlib.new(hashAlgo.name, ipad).digest() + hashlib.new(hashAlgo.name, opad).digest()
            k = cipherAlgo.do_fixup_key(k)
            return k
         */

        public static byte[] DeriveKey(byte[] keyBytes, byte[] saltBytes, int algHash, byte[] entropy = null)
        {
            // derives a dpapi session key using Microsoft crypto "magic"

            //Console.WriteLine("[*] key       : {0}", BitConverter.ToString(keyBytes).Replace("-", ""));
            //Console.WriteLine("[*] saltBytes : {0}", BitConverter.ToString(saltBytes).Replace("-", ""));
            //Console.WriteLine("[*] entropy   : {0}", BitConverter.ToString(entropy).Replace("-", ""));
            //Console.WriteLine("[*] algHash   : {0}", (HashAlgorithm)algHash);

            if (algHash == (int)HashAlgorithm.CALG_SHA_512)
            {
                // TODO: pretty sure this is wrong. It only calculates the session key but doesn't do derivation

                // calculate the session key -> HMAC(salt) where the sha1(masterkey) is the key

                // 32782 == CALG_SHA_512
                // https://github.com/gentilkiwi/mimikatz/blob/fa42ed93aa4d5aa73825295e2ab757ac96005581/modules/kull_m_dpapi.c#L500
                if (entropy != null)
                {
                    return HMACSha512(keyBytes, Helpers.Combine(saltBytes, entropy));
                }
                else
                {
                    return HMACSha512(keyBytes, saltBytes);
                }
            } else if (algHash == (int)HashAlgorithm.CALG_SHA1)
            {
                // 32772 == CALG_SHA1

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
                    ipad[i] ^= keyBytes[i];
                    opad[i] ^= keyBytes[i];
                }

                byte[] bufferI = Helpers.Combine(ipad, saltBytes);
                
                using (var sha1 = new SHA1Managed())
                {
                    var sha1BufferI = sha1.ComputeHash(bufferI);
                    
                    byte[] bufferO = Helpers.Combine(opad, sha1BufferI);
                    if(entropy != null)
                    {
                        bufferO = Helpers.Combine(bufferO, entropy);
                    }

                    var sha1Buffer0 = sha1.ComputeHash(bufferO);
                    
                    return DeriveKeyRaw(sha1Buffer0, algHash);
                }
            }
            else
            {
                Console.WriteLine("[!] Unsupported Hash Algorithm");
                return new byte[0];
            }
        }


        // adapted from https://github.com/gentilkiwi/mimikatz/blob/fa42ed93aa4d5aa73825295e2ab757ac96005581/modules/kull_m_crypto.c#L79-L101
        public static byte[] DeriveKeyRaw(byte[] hashBytes, int algHash)
        {
            var ipad = new byte[64];
            var opad = new byte[64];

            // "...wut" - anyone reading Microsoft crypto
            for (var i = 0; i < 64; i++)
            {
                ipad[i] = Convert.ToByte('6');
                opad[i] = Convert.ToByte('\\');
            }

            for (var i = 0; i < hashBytes.Length; i++)
            {
                ipad[i] ^= hashBytes[i];
                opad[i] ^= hashBytes[i];
            }

            if (algHash == 32772)
            {
                using (var sha1 = new SHA1Managed())
                {
                    var ipadSHA1bytes = sha1.ComputeHash(ipad);
                    var ppadSHA1bytes = sha1.ComputeHash(opad);
                    return Helpers.Combine(ipadSHA1bytes, ppadSHA1bytes);
                }
            }
            else
            {
                Console.WriteLine("[X] Alghash not yet implemented: {0}", algHash);
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