using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace SharpDPAPI
{
    public class Crypto
    {
        public static byte[] DecryptBlob(byte[] ciphertext, byte[] key, int algCrypt = 26115)
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
                desCryptoProvider.Padding = PaddingMode.Zeros;

                byte[] plaintextBytes = desCryptoProvider.CreateDecryptor().TransformFinalBlock(ciphertext, 0, ciphertext.Length);

                return plaintextBytes;
            }
            else if (algCrypt == 26128)
            {
                // takes a byte array of ciphertext bytes and a key array, decrypt the blob with AES256
                AesManaged aesCryptoProvider = new AesManaged();

                byte[] ivBytes = new byte[16];

                aesCryptoProvider.Key = key;
                aesCryptoProvider.IV = ivBytes;
                aesCryptoProvider.Mode = CipherMode.CBC;
                aesCryptoProvider.Padding = PaddingMode.Zeros;

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
    }
}