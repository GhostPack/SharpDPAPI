using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Runtime.InteropServices;

namespace SharpChrome
{
    public class BCrypt
    {
        // adapted from https://github.com/AArnott/pinvoke/blob/master/src/BCrypt/
        // Author: @AArnott
        // License: MIT

        #region Structs

        [StructLayout(LayoutKind.Sequential)]
        //[OfferIntPtrPropertyAccessors]
        public unsafe partial struct BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO
        {
            public const uint BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION = 1;

            public int cbSize;

            public uint dwInfoVersion;

            public byte* pbNonce;

            public int cbNonce;

            public byte* pbAuthData;

            public int cbAuthData;

            public byte* pbTag;

            public int cbTag;

            public byte* pbMacContext;

            public int cbMacContext;

            public int cbAAD;

            public long cbData;

            public AuthModeFlags dwFlags;

            public static BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO Create()
            {
                return new BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO
                {
                    cbSize = Marshal.SizeOf(typeof(BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO)),
                    dwInfoVersion = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION,
                };
            }
        }

        #endregion


        #region Enums

        [Flags]
        public enum AuthModeFlags
        {
            None = 0x0,

            BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG = 0x1,

            BCRYPT_AUTH_MODE_IN_PROGRESS_FLAG = 0x2,
        }

        [Flags]
        public enum BCryptCloseAlgorithmProviderFlags
        {
            None = 0x0,
        }

        [Flags]
        public enum BCryptOpenAlgorithmProviderFlags
        {
            None = 0x0,

            BCRYPT_ALG_HANDLE_HMAC_FLAG = 0x8,

            BCRYPT_HASH_REUSABLE_FLAG = 0x20,

            BCRYPT_MULTI_FLAG = 0x40,
        }

        public enum BCryptSetPropertyFlags
        {
            None = 0x0,
        }

        [Flags]
        public enum BCryptGenerateSymmetricKeyFlags
        {
            None = 0x0,
        }

        [Flags]
        public enum BCryptEncryptFlags
        {
            None = 0x0,

            BCRYPT_BLOCK_PADDING = 1,

            BCRYPT_PAD_NONE = 0x1,

            BCRYPT_PAD_PKCS1 = 0x2,

            BCRYPT_PAD_OAEP = 0x4,
        }

        # endregion 


        #region Functions

        [DllImport(nameof(BCrypt), SetLastError = true, ExactSpelling = true)]
        public static extern uint BCryptDestroyKey(
            IntPtr hKey);

        [DllImport(nameof(BCrypt), SetLastError = true, ExactSpelling = true)]
        public static extern uint BCryptCloseAlgorithmProvider(
            IntPtr algorithmHandle,
            BCryptCloseAlgorithmProviderFlags flags = BCryptCloseAlgorithmProviderFlags.None);

        [DllImport(nameof(BCrypt), SetLastError = true, CharSet = CharSet.Unicode, ExactSpelling = true)]
        public static extern uint BCryptOpenAlgorithmProvider(
            out SafeAlgorithmHandle phAlgorithm,
            string pszAlgId,
            string pszImplementation,
            BCryptOpenAlgorithmProviderFlags dwFlags);

        [DllImport(nameof(BCrypt), SetLastError = true, ExactSpelling = true, CharSet = CharSet.Unicode)]
        public static extern uint BCryptSetProperty(
            SafeHandle hObject,
            string pszProperty,
            string pbInput,
            int cbInput,
            BCryptSetPropertyFlags dwFlags = BCryptSetPropertyFlags.None);

        [DllImport(nameof(BCrypt), SetLastError = true)]
        public static extern uint BCryptGenerateSymmetricKey(
            SafeAlgorithmHandle hAlgorithm,
            out SafeKeyHandle phKey,
            byte[] pbKeyObject,
            int cbKeyObject,
            byte[] pbSecret,
            int cbSecret,
            BCryptGenerateSymmetricKeyFlags flags = BCryptGenerateSymmetricKeyFlags.None);

        [DllImport(nameof(BCrypt), SetLastError = true)]
        public static unsafe extern uint BCryptDecrypt(
            SafeKeyHandle hKey,
            byte* pbInput,
            int cbInput,
            void* pPaddingInfo,
            byte* pbIV,
            int cbIV,
            byte* pbOutput,
            int cbOutput,
            out int pcbResult,
            BCryptEncryptFlags dwFlags);

        #endregion


        #region Classes
        public class SafeKeyHandle : SafeHandle
        {
            public static readonly SafeKeyHandle Null = new SafeKeyHandle();

            public SafeKeyHandle()
                : base(IntPtr.Zero, true)
            {
            }

            public SafeKeyHandle(IntPtr preexistingHandle, bool ownsHandle = true)
                : base(IntPtr.Zero, ownsHandle)
            {
                this.SetHandle(preexistingHandle);
            }

            public override bool IsInvalid => this.handle == IntPtr.Zero;

            protected override bool ReleaseHandle()
            {
                // 0x0 == STATUS_SUCCESS
                return BCryptDestroyKey(this.handle) == 0x0;
            }
        }

        public class SafeAlgorithmHandle : SafeHandle
        {
            public static readonly SafeAlgorithmHandle Null = new SafeAlgorithmHandle();

            public SafeAlgorithmHandle()
                : base(IntPtr.Zero, true)
            {
            }

            public SafeAlgorithmHandle(IntPtr preexistingHandle, bool ownsHandle = true)
                : base(IntPtr.Zero, ownsHandle)
            {
                this.SetHandle(preexistingHandle);
            }

            public override bool IsInvalid => this.handle == IntPtr.Zero;

            protected override bool ReleaseHandle()
            {
                // 0x0 == STATUS_SUCCESS
                return BCryptCloseAlgorithmProvider(this.handle, 0) == 0;
            }
        }

        #endregion


        #region Helperse

        public static void BCRYPT_INIT_AUTH_MODE_INFO(out BCrypt.BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO _AUTH_INFO_STRUCT_)
        {
            _AUTH_INFO_STRUCT_ = new BCrypt.BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO();
            _AUTH_INFO_STRUCT_.cbSize = Marshal.SizeOf(typeof(BCrypt.BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO));
            _AUTH_INFO_STRUCT_.dwInfoVersion = 1;
        }

        #endregion
    }
}