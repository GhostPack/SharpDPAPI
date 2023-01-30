using System;
using System.Security.Policy;
using System.Text;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace SharpChrome.Extensions
{
    public static class BouncyCastleExtensions
    {
        public static byte[] EncryptWithGcm(byte[] plaintextBytes, byte[] key, byte[] nonce)
        {
            var tagLength = 16;

            var ciphertextTagBytes = new byte[plaintextBytes.Length + tagLength];

            var cipher = new GcmBlockCipher(new AesEngine());
            var parameters = new AeadParameters(new KeyParameter(key), tagLength * 8, nonce);
            cipher.Init(true, parameters);

            var offset = cipher.ProcessBytes(plaintextBytes, 0, plaintextBytes.Length, ciphertextTagBytes, 0);
            cipher.DoFinal(ciphertextTagBytes, offset); // create and append tag: ciphertext | tag

            return ciphertextTagBytes;
        }

        public static byte[] DecryptWithGcm(byte[] ciphertextTagBytes, byte[] key, byte[] nonce = null)
        {
            var tagLength = 16;

            if (nonce == null) {
                nonce = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
                //trim first 3 bytes(signature "v10") and take 12 bytes after signature.
                const int nonceLength = 12;
                Array.Copy(ciphertextTagBytes, 3, nonce, 0, nonceLength);
            }

            var plaintextBytes = new byte[ciphertextTagBytes.Length - tagLength];
            byte[] tag = new byte[tagLength]; // AuthTag
            Array.Copy(ciphertextTagBytes, ciphertextTagBytes.Length - tagLength, tag, 0, tagLength);

            var cipher = new GcmBlockCipher(new AesEngine());
            var parameters = new AeadParameters(new KeyParameter(key), 8 * 16, nonce);
            cipher.Init(false, parameters);

            var offset = cipher.ProcessBytes(ciphertextTagBytes, 0, ciphertextTagBytes.Length, plaintextBytes, 0);
            cipher.DoFinal(plaintextBytes, offset); // authenticate data via tag

            return plaintextBytes;
        }

        public static byte[] GetNonce(byte[] encryptedBytesConcatenatedWithTag)
        {
            var tagLength = 16;

            var nonce = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }; // IV 12 bytes

            //trim first 3 bytes(signature "v10") and take 12 bytes after signature.
            const int nonceLength = 12;
            Array.Copy(encryptedBytesConcatenatedWithTag, 3, nonce, 0, nonceLength);

            return nonce;
        }
    }
}