namespace SharpChrome.Extensions
{
//Requires PInvoke.BCrypt
//Note that AES GCM encryption is included on .Net Core 3.0, but not in the full .Net framework.
//This implementation requires PInvoke.BCrypt, and reulies on the Windows CNG Bcrypt library which
//is available on Windows Vista or later.  Note also the requirement for unsafe code.
//As coded requires VS 2015 / C#6 or above.

    using System;
    using PInvoke;
    using static PInvoke.BCrypt;
    using System.Security.Cryptography;

    public unsafe static class AESGCM
    {
        public unsafe static byte[] GcmEncrypt(byte[] pbData, byte[] pbKey, byte[] pbNonce, byte[] pbTag,
            byte[] pbAuthData = null)
        {
            pbAuthData = pbAuthData ?? new byte[0];

            NTSTATUS status = 0;

            using (var provider = BCryptOpenAlgorithmProvider(AlgorithmIdentifiers.BCRYPT_AES_ALGORITHM)) {
                BCryptSetProperty(provider, PropertyNames.BCRYPT_CHAINING_MODE, ChainingModes.Gcm);

                var tagLengths =
                    BCryptGetProperty<BCRYPT_AUTH_TAG_LENGTHS_STRUCT>(provider, PropertyNames.BCRYPT_AUTH_TAG_LENGTH);

                if (pbTag.Length < tagLengths.dwMinLength
                    || pbTag.Length > tagLengths.dwMaxLength
                    || (pbTag.Length - tagLengths.dwMinLength) % tagLengths.dwIncrement != 0)
                    throw new ArgumentException("Invalid tag length");

                using (var key = BCryptGenerateSymmetricKey(provider, pbKey)) {
                    var authInfo = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO.Create();
                    fixed (byte* pTagBuffer = pbTag)
                    fixed (byte* pNonce = pbNonce)
                    fixed (byte* pAuthData = pbAuthData) {
                        authInfo.pbNonce = pNonce;
                        authInfo.cbNonce = pbNonce.Length;
                        authInfo.pbTag = pTagBuffer;
                        authInfo.cbTag = pbTag.Length;
                        authInfo.pbAuthData = pAuthData;
                        authInfo.cbAuthData = pbAuthData.Length;

                        //Initialize Cipher Text Byte Count
                        int pcbCipherText = pbData.Length;

                        //Allocate Cipher Text Buffer
                        byte[] pbCipherText = new byte[pcbCipherText];

                        fixed (byte* plainText = pbData)
                        fixed (byte* cipherText = pbCipherText) {
                            //Encrypt The Data
                            status = BCryptEncrypt(
                                key,
                                plainText,
                                pbData.Length,
                                &authInfo,
                                null,
                                0,
                                cipherText,
                                pbCipherText.Length,
                                out pcbCipherText,
                                0);
                        }

                        if (status != NTSTATUS.Code.STATUS_SUCCESS)
                            throw new CryptographicException($"BCryptEncrypt failed result {status:X} ");

                        return pbCipherText;
                    }
                }
            }
        }

        public unsafe static byte[] GcmDecrypt(byte[] pbData, byte[] pbKey, byte[] pbNonce, byte[] pbTag,
            byte[] pbAuthData = null)
        {
            pbAuthData = pbAuthData ?? new byte[0];

            NTSTATUS status = 0;

            using (var provider = BCryptOpenAlgorithmProvider(AlgorithmIdentifiers.BCRYPT_AES_ALGORITHM)) {
                BCryptSetProperty(provider, PropertyNames.BCRYPT_CHAINING_MODE, ChainingModes.Gcm);

                var tagLengths =
                    BCryptGetProperty<BCRYPT_AUTH_TAG_LENGTHS_STRUCT>(provider, PropertyNames.BCRYPT_AUTH_TAG_LENGTH);

                if (pbTag.Length < tagLengths.dwMinLength
                    || pbTag.Length > tagLengths.dwMaxLength
                    || (pbTag.Length - tagLengths.dwMinLength) % tagLengths.dwIncrement != 0)
                    throw new ArgumentException("Invalid tag length");

                using (var key = BCryptGenerateSymmetricKey(provider, pbKey)) {
                    var authInfo = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO.Create();
                    fixed (byte* pTagBuffer = pbTag)
                    fixed (byte* pNonce = pbNonce)
                    fixed (byte* pAuthData = pbAuthData) {
                        authInfo.pbNonce = pNonce;
                        authInfo.cbNonce = pbNonce.Length;
                        authInfo.pbTag = pTagBuffer;
                        authInfo.cbTag = pbTag.Length;
                        authInfo.pbAuthData = pAuthData;
                        authInfo.cbAuthData = pbAuthData.Length;

                        //Initialize Cipher Text Byte Count
                        int pcbPlaintext = pbData.Length;

                        //Allocate Plaintext Buffer
                        byte[] pbPlaintext = new byte[pcbPlaintext];

                        fixed (byte* ciphertext = pbData)
                        fixed (byte* plaintext = pbPlaintext) {
                            //Decrypt The Data
                            status = BCryptDecrypt(
                                key,
                                ciphertext,
                                pbData.Length,
                                &authInfo,
                                null,
                                0,
                                plaintext,
                                pbPlaintext.Length,
                                out pcbPlaintext,
                                0);
                        }

                        if (status == NTSTATUS.Code.STATUS_AUTH_TAG_MISMATCH)
                            throw new CryptographicException("BCryptDecrypt auth tag mismatch");
                        else if (status != NTSTATUS.Code.STATUS_SUCCESS)
                            throw new CryptographicException($"BCryptDecrypt failed result {status:X} ");

                        return pbPlaintext;
                    }
                }
            }
        }
    }
}