using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;

namespace SharpDPAPI
{
    public class Interop
    {
        public enum CryptAlgClass : uint
        {
            ALG_CLASS_ANY = (0),
            ALG_CLASS_SIGNATURE = (1 << 13),
            ALG_CLASS_MSG_ENCRYPT = (2 << 13),
            ALG_CLASS_DATA_ENCRYPT = (3 << 13),
            ALG_CLASS_HASH = (4 << 13),
            ALG_CLASS_KEY_EXCHANGE = (5 << 13),
            ALG_CLASS_ALL = (7 << 13)
        }

        public enum CryptAlgType : uint
        {
            ALG_TYPE_ANY = (0),
            ALG_TYPE_DSS = (1 << 9),
            ALG_TYPE_RSA = (2 << 9),
            ALG_TYPE_BLOCK = (3 << 9),
            ALG_TYPE_STREAM = (4 << 9),
            ALG_TYPE_DH = (5 << 9),
            ALG_TYPE_SECURECHANNEL = (6 << 9)
        }

        public enum CryptAlgSID : uint
        {
            ALG_SID_ANY = (0),
            ALG_SID_RSA_ANY = 0,
            ALG_SID_RSA_PKCS = 1,
            ALG_SID_RSA_MSATWORK = 2,
            ALG_SID_RSA_ENTRUST = 3,
            ALG_SID_RSA_PGP = 4,
            ALG_SID_DSS_ANY = 0,
            ALG_SID_DSS_PKCS = 1,
            ALG_SID_DSS_DMS = 2,
            ALG_SID_ECDSA = 3,
            ALG_SID_DES = 1,
            ALG_SID_3DES = 3,
            ALG_SID_DESX = 4,
            ALG_SID_IDEA = 5,
            ALG_SID_CAST = 6,
            ALG_SID_SAFERSK64 = 7,
            ALG_SID_SAFERSK128 = 8,
            ALG_SID_3DES_112 = 9,
            ALG_SID_CYLINK_MEK = 12,
            ALG_SID_RC5 = 13,
            ALG_SID_AES_128 = 14,
            ALG_SID_AES_192 = 15,
            ALG_SID_AES_256 = 16,
            ALG_SID_AES = 17,
            ALG_SID_SKIPJACK = 10,
            ALG_SID_TEK = 11,
            ALG_SID_RC2 = 2,
            ALG_SID_RC4 = 1,
            ALG_SID_SEAL = 2,
            ALG_SID_DH_SANDF = 1,
            ALG_SID_DH_EPHEM = 2,
            ALG_SID_AGREED_KEY_ANY = 3,
            ALG_SID_KEA = 4,
            ALG_SID_ECDH = 5,
            ALG_SID_MD2 = 1,
            ALG_SID_MD4 = 2,
            ALG_SID_MD5 = 3,
            ALG_SID_SHA = 4,
            ALG_SID_SHA1 = 4,
            ALG_SID_MAC = 5,
            ALG_SID_RIPEMD = 6,
            ALG_SID_RIPEMD160 = 7,
            ALG_SID_SSL3SHAMD5 = 8,
            ALG_SID_HMAC = 9,
            ALG_SID_TLS1PRF = 10,
            ALG_SID_HASH_REPLACE_OWF = 11,
            ALG_SID_SHA_256 = 12,
            ALG_SID_SHA_384 = 13,
            ALG_SID_SHA_512 = 14,
            ALG_SID_SSL3_MASTER = 1,
            ALG_SID_SCHANNEL_MASTER_HASH = 2,
            ALG_SID_SCHANNEL_MAC_KEY = 3,
            ALG_SID_PCT1_MASTER = 4,
            ALG_SID_SSL2_MASTER = 5,
            ALG_SID_TLS1_MASTER = 6,
            ALG_SID_SCHANNEL_ENC_KEY = 7,
            ALG_SID_ECMQV = 1
        }

        public enum CryptAlg : uint
        {
            CALG_MD2 = (CryptAlgClass.ALG_CLASS_HASH | CryptAlgType.ALG_TYPE_ANY | CryptAlgSID.ALG_SID_MD2),
            CALG_MD4 = (CryptAlgClass.ALG_CLASS_HASH | CryptAlgType.ALG_TYPE_ANY | CryptAlgSID.ALG_SID_MD4),
            CALG_MD5 = (CryptAlgClass.ALG_CLASS_HASH | CryptAlgType.ALG_TYPE_ANY | CryptAlgSID.ALG_SID_MD5),
            CALG_SHA = (CryptAlgClass.ALG_CLASS_HASH | CryptAlgType.ALG_TYPE_ANY | CryptAlgSID.ALG_SID_SHA),
            CALG_SHA1 = (CryptAlgClass.ALG_CLASS_HASH | CryptAlgType.ALG_TYPE_ANY | CryptAlgSID.ALG_SID_SHA1),
            CALG_MAC = (CryptAlgClass.ALG_CLASS_HASH | CryptAlgType.ALG_TYPE_ANY | CryptAlgSID.ALG_SID_MAC),
            CALG_RSA_SIGN = (CryptAlgClass.ALG_CLASS_SIGNATURE | CryptAlgType.ALG_TYPE_RSA | CryptAlgSID.ALG_SID_RSA_ANY),
            CALG_DSS_SIGN = (CryptAlgClass.ALG_CLASS_SIGNATURE | CryptAlgType.ALG_TYPE_DSS | CryptAlgSID.ALG_SID_DSS_ANY),
            CALG_NO_SIGN = (CryptAlgClass.ALG_CLASS_SIGNATURE | CryptAlgType.ALG_TYPE_ANY | CryptAlgSID.ALG_SID_ANY),
            CALG_RSA_KEYX = (CryptAlgClass.ALG_CLASS_KEY_EXCHANGE | CryptAlgType.ALG_TYPE_RSA | CryptAlgSID.ALG_SID_RSA_ANY),
            CALG_DES = (CryptAlgClass.ALG_CLASS_DATA_ENCRYPT | CryptAlgType.ALG_TYPE_BLOCK | CryptAlgSID.ALG_SID_DES),
            CALG_3DES_112 = (CryptAlgClass.ALG_CLASS_DATA_ENCRYPT | CryptAlgType.ALG_TYPE_BLOCK | CryptAlgSID.ALG_SID_3DES_112),
            CALG_3DES = (CryptAlgClass.ALG_CLASS_DATA_ENCRYPT | CryptAlgType.ALG_TYPE_BLOCK | CryptAlgSID.ALG_SID_3DES),
            CALG_DESX = (CryptAlgClass.ALG_CLASS_DATA_ENCRYPT | CryptAlgType.ALG_TYPE_BLOCK | CryptAlgSID.ALG_SID_DESX),
            CALG_RC2 = (CryptAlgClass.ALG_CLASS_DATA_ENCRYPT | CryptAlgType.ALG_TYPE_BLOCK | CryptAlgSID.ALG_SID_RC2),
            CALG_RC4 = (CryptAlgClass.ALG_CLASS_DATA_ENCRYPT | CryptAlgType.ALG_TYPE_STREAM | CryptAlgSID.ALG_SID_RC4),
            CALG_SEAL = (CryptAlgClass.ALG_CLASS_DATA_ENCRYPT | CryptAlgType.ALG_TYPE_STREAM | CryptAlgSID.ALG_SID_SEAL),
            CALG_DH_SF = (CryptAlgClass.ALG_CLASS_KEY_EXCHANGE | CryptAlgType.ALG_TYPE_DH | CryptAlgSID.ALG_SID_DH_SANDF),
            CALG_DH_EPHEM = (CryptAlgClass.ALG_CLASS_KEY_EXCHANGE | CryptAlgType.ALG_TYPE_DH | CryptAlgSID.ALG_SID_DH_EPHEM),
            CALG_AGREEDKEY_ANY = (CryptAlgClass.ALG_CLASS_KEY_EXCHANGE | CryptAlgType.ALG_TYPE_DH | CryptAlgSID.ALG_SID_AGREED_KEY_ANY),
            CALG_KEA_KEYX = (CryptAlgClass.ALG_CLASS_KEY_EXCHANGE | CryptAlgType.ALG_TYPE_DH | CryptAlgSID.ALG_SID_KEA),
            CALG_HUGHES_MD5 = (CryptAlgClass.ALG_CLASS_KEY_EXCHANGE | CryptAlgType.ALG_TYPE_ANY | CryptAlgSID.ALG_SID_MD5),
            CALG_SKIPJACK = (CryptAlgClass.ALG_CLASS_DATA_ENCRYPT | CryptAlgType.ALG_TYPE_BLOCK | CryptAlgSID.ALG_SID_SKIPJACK),
            CALG_TEK = (CryptAlgClass.ALG_CLASS_DATA_ENCRYPT | CryptAlgType.ALG_TYPE_BLOCK | CryptAlgSID.ALG_SID_TEK),
            CALG_CYLINK_MEK = (CryptAlgClass.ALG_CLASS_DATA_ENCRYPT | CryptAlgType.ALG_TYPE_BLOCK | CryptAlgSID.ALG_SID_CYLINK_MEK),
            CALG_SSL3_SHAMD5 = (CryptAlgClass.ALG_CLASS_HASH | CryptAlgType.ALG_TYPE_ANY | CryptAlgSID.ALG_SID_SSL3SHAMD5),
            CALG_SSL3_MASTER = (CryptAlgClass.ALG_CLASS_MSG_ENCRYPT | CryptAlgType.ALG_TYPE_SECURECHANNEL | CryptAlgSID.ALG_SID_SSL3_MASTER),
            CALG_SCHANNEL_MASTER_HASH = (CryptAlgClass.ALG_CLASS_MSG_ENCRYPT | CryptAlgType.ALG_TYPE_SECURECHANNEL | CryptAlgSID.ALG_SID_SCHANNEL_MASTER_HASH),
            CALG_SCHANNEL_MAC_KEY = (CryptAlgClass.ALG_CLASS_MSG_ENCRYPT | CryptAlgType.ALG_TYPE_SECURECHANNEL | CryptAlgSID.ALG_SID_SCHANNEL_MAC_KEY),
            CALG_SCHANNEL_ENC_KEY = (CryptAlgClass.ALG_CLASS_MSG_ENCRYPT | CryptAlgType.ALG_TYPE_SECURECHANNEL | CryptAlgSID.ALG_SID_SCHANNEL_ENC_KEY),
            CALG_PCT1_MASTER = (CryptAlgClass.ALG_CLASS_MSG_ENCRYPT | CryptAlgType.ALG_TYPE_SECURECHANNEL | CryptAlgSID.ALG_SID_PCT1_MASTER),
            CALG_SSL2_MASTER = (CryptAlgClass.ALG_CLASS_MSG_ENCRYPT | CryptAlgType.ALG_TYPE_SECURECHANNEL | CryptAlgSID.ALG_SID_SSL2_MASTER),
            CALG_TLS1_MASTER = (CryptAlgClass.ALG_CLASS_MSG_ENCRYPT | CryptAlgType.ALG_TYPE_SECURECHANNEL | CryptAlgSID.ALG_SID_TLS1_MASTER),
            CALG_RC5 = (CryptAlgClass.ALG_CLASS_DATA_ENCRYPT | CryptAlgType.ALG_TYPE_BLOCK | CryptAlgSID.ALG_SID_RC5),
            CALG_HMAC = (CryptAlgClass.ALG_CLASS_HASH | CryptAlgType.ALG_TYPE_ANY | CryptAlgSID.ALG_SID_HMAC),
            CALG_TLS1PRF = (CryptAlgClass.ALG_CLASS_HASH | CryptAlgType.ALG_TYPE_ANY | CryptAlgSID.ALG_SID_TLS1PRF),
            CALG_HASH_REPLACE_OWF = (CryptAlgClass.ALG_CLASS_HASH | CryptAlgType.ALG_TYPE_ANY | CryptAlgSID.ALG_SID_HASH_REPLACE_OWF),
            CALG_AES_128 = (CryptAlgClass.ALG_CLASS_DATA_ENCRYPT | CryptAlgType.ALG_TYPE_BLOCK | CryptAlgSID.ALG_SID_AES_128),
            CALG_AES_192 = (CryptAlgClass.ALG_CLASS_DATA_ENCRYPT | CryptAlgType.ALG_TYPE_BLOCK | CryptAlgSID.ALG_SID_AES_192),
            CALG_AES_256 = (CryptAlgClass.ALG_CLASS_DATA_ENCRYPT | CryptAlgType.ALG_TYPE_BLOCK | CryptAlgSID.ALG_SID_AES_256),
            CALG_AES = (CryptAlgClass.ALG_CLASS_DATA_ENCRYPT | CryptAlgType.ALG_TYPE_BLOCK | CryptAlgSID.ALG_SID_AES),
            CALG_SHA_256 = (CryptAlgClass.ALG_CLASS_HASH | CryptAlgType.ALG_TYPE_ANY | CryptAlgSID.ALG_SID_SHA_256),
            CALG_SHA_384 = (CryptAlgClass.ALG_CLASS_HASH | CryptAlgType.ALG_TYPE_ANY | CryptAlgSID.ALG_SID_SHA_384),
            CALG_SHA_512 = (CryptAlgClass.ALG_CLASS_HASH | CryptAlgType.ALG_TYPE_ANY | CryptAlgSID.ALG_SID_SHA_512),
            CALG_ECDH = (CryptAlgClass.ALG_CLASS_KEY_EXCHANGE | CryptAlgType.ALG_TYPE_DH | CryptAlgSID.ALG_SID_ECDH),
            CALG_ECMQV = (CryptAlgClass.ALG_CLASS_KEY_EXCHANGE | CryptAlgType.ALG_TYPE_ANY | CryptAlgSID.ALG_SID_ECMQV),
            CALG_ECDSA = (CryptAlgClass.ALG_CLASS_SIGNATURE | CryptAlgType.ALG_TYPE_DSS | CryptAlgSID.ALG_SID_ECDSA)
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LSA_UNICODE_STRING : IDisposable
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr buffer;

            public LSA_UNICODE_STRING(string s)
            {
                Length = (ushort)(s.Length * 2);
                MaximumLength = (ushort)(Length + 2);
                buffer = Marshal.StringToHGlobalUni(s);
            }

            public void Dispose()
            {
                Marshal.FreeHGlobal(buffer);
                buffer = IntPtr.Zero;
            }

            public override string ToString()
            {
                return Marshal.PtrToStringUni(buffer);
            }
        }

        // From Vincent LE TOUX' "MakeMeEnterpriseAdmin"
        //  https://github.com/vletoux/MakeMeEnterpriseAdmin/blob/master/MakeMeEnterpriseAdmin.ps1#L1773-L1794
        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_ECRYPT
        {
            int Type0;
            public int BlockSize;
            int Type1;
            public int KeySize;
            public int Size;
            int unk2;
            int unk3;
            public IntPtr AlgName;
            public IntPtr Initialize;
            public IntPtr Encrypt;
            public IntPtr Decrypt;
            public IntPtr Finish;
            public IntPtr HashPassword;
            IntPtr RandomKey;
            IntPtr Control;
            IntPtr unk0_null;
            IntPtr unk1_null;
            IntPtr unk2_null;
        }

        public enum KERB_ETYPE : UInt32
        {
            des_cbc_crc = 1,
            des_cbc_md4 = 2,
            des_cbc_md5 = 3,
            des3_cbc_md5 = 5,
            des3_cbc_sha1 = 7,
            dsaWithSHA1_CmsOID = 9,
            md5WithRSAEncryption_CmsOID = 10,
            sha1WithRSAEncryption_CmsOID = 11,
            rc2CBC_EnvOID = 12,
            rsaEncryption_EnvOID = 13,
            rsaES_OAEP_ENV_OID = 14,
            des_ede3_cbc_Env_OID = 15,
            des3_cbc_sha1_kd = 16,
            aes128_cts_hmac_sha1 = 17,
            aes256_cts_hmac_sha1 = 18,
            rc4_hmac = 23,
            rc4_hmac_exp = 24,
            subkey_keymaterial = 65
        }

        public enum POLICY_INFORMATION_CLASS
        {
            PolicyAuditLogInformation = 1,
            PolicyAuditEventsInformation,
            PolicyPrimaryDomainInformation,
            PolicyPdAccountInformation,
            PolicyAccountDomainInformation,
            PolicyLsaServerRoleInformation,
            PolicyReplicaSourceInformation,
            PolicyDefaultQuotaInformation,
            PolicyModificationInformation,
            PolicyAuditFullSetInformation,
            PolicyAuditFullQueryInformation,
            PolicyDnsDomainInformation
        }

        public enum LSA_AccessPolicy : long
        {
            POLICY_VIEW_LOCAL_INFORMATION = 0x00000001L,
            POLICY_VIEW_AUDIT_INFORMATION = 0x00000002L,
            POLICY_GET_PRIVATE_INFORMATION = 0x00000004L,
            POLICY_TRUST_ADMIN = 0x00000008L,
            POLICY_CREATE_ACCOUNT = 0x00000010L,
            POLICY_CREATE_SECRET = 0x00000020L,
            POLICY_CREATE_PRIVILEGE = 0x00000040L,
            POLICY_SET_DEFAULT_QUOTA_LIMITS = 0x00000080L,
            POLICY_SET_AUDIT_REQUIREMENTS = 0x00000100L,
            POLICY_AUDIT_LOG_ADMIN = 0x00000200L,
            POLICY_SERVER_ADMIN = 0x00000400L,
            POLICY_LOOKUP_NAMES = 0x00000800L,
            POLICY_NOTIFICATION = 0x00001000L
        }

        public struct LSA_OBJECT_ATTRIBUTES
        {
            public UInt32 Length;
            public IntPtr RootDirectory;
            public LSA_UNICODE_STRING ObjectName;
            public UInt32 Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct UNICODE_STRING : IDisposable
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr buffer;

            public UNICODE_STRING(string s)
            {
                Length = (ushort)(s.Length * 2);
                MaximumLength = (ushort)(Length + 2);
                buffer = Marshal.StringToHGlobalUni(s);
            }

            public void Dispose()
            {
                Marshal.FreeHGlobal(buffer);
                buffer = IntPtr.Zero;
            }

            public override string ToString()
            {
                return Marshal.PtrToStringUni(buffer);
            }
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct DOMAIN_CONTROLLER_INFO
        {
            [MarshalAs(UnmanagedType.LPTStr)]
            public string DomainControllerName;
            [MarshalAs(UnmanagedType.LPTStr)]
            public string DomainControllerAddress;
            public uint DomainControllerAddressType;
            public Guid DomainGuid;
            [MarshalAs(UnmanagedType.LPTStr)]
            public string DomainName;
            [MarshalAs(UnmanagedType.LPTStr)]
            public string DnsForestName;
            public uint Flags;
            [MarshalAs(UnmanagedType.LPTStr)]
            public string DcSiteName;
            [MarshalAs(UnmanagedType.LPTStr)]
            public string ClientSiteName;
        }

        [Flags]
        public enum DSGETDCNAME_FLAGS : uint
        {
            DS_FORCE_REDISCOVERY = 0x00000001,
            DS_DIRECTORY_SERVICE_REQUIRED = 0x00000010,
            DS_DIRECTORY_SERVICE_PREFERRED = 0x00000020,
            DS_GC_SERVER_REQUIRED = 0x00000040,
            DS_PDC_REQUIRED = 0x00000080,
            DS_BACKGROUND_ONLY = 0x00000100,
            DS_IP_REQUIRED = 0x00000200,
            DS_KDC_REQUIRED = 0x00000400,
            DS_TIMESERV_REQUIRED = 0x00000800,
            DS_WRITABLE_REQUIRED = 0x00001000,
            DS_GOOD_TIMESERV_PREFERRED = 0x00002000,
            DS_AVOID_SELF = 0x00004000,
            DS_ONLY_LDAP_NEEDED = 0x00008000,
            DS_IS_FLAT_NAME = 0x00010000,
            DS_IS_DNS_NAME = 0x00020000,
            DS_RETURN_DNS_NAME = 0x40000000,
            DS_RETURN_FLAT_NAME = 0x80000000
        }
        public delegate int KERB_ECRYPT_HashPassword(UNICODE_STRING Password, UNICODE_STRING Salt, int count, byte[] output);

        // Adapted from Vincent LE TOUX' "MakeMeEnterpriseAdmin"
        [DllImport("cryptdll.Dll", CharSet = CharSet.Auto, SetLastError = false)]
        public static extern int CDLocateCSystem(KERB_ETYPE type, out IntPtr pCheckSum);
        // for remote backup key retrieval
        [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
        public static extern uint LsaOpenPolicy(
           ref LSA_UNICODE_STRING SystemName,
           ref LSA_OBJECT_ATTRIBUTES ObjectAttributes,
           uint DesiredAccess,
           out IntPtr PolicyHandle
        );

        [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
        public static extern uint LsaRetrievePrivateData(
            IntPtr PolicyHandle,
            ref LSA_UNICODE_STRING KeyName,
            out IntPtr PrivateData
        );

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern uint LsaNtStatusToWinError(uint status);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern uint LsaClose(IntPtr ObjectHandle);

        [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
        public static extern uint LsaFreeMemory(
            IntPtr buffer
        );


        // for GetSystem()
        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool OpenProcessToken(
            IntPtr ProcessHandle,
            UInt32 DesiredAccess,
            out IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool DuplicateToken(
            IntPtr ExistingTokenHandle,
            int SECURITY_IMPERSONATION_LEVEL,
            ref IntPtr DuplicateTokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool ImpersonateLoggedOnUser(
            IntPtr hToken);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
                public static extern bool CloseHandle(
            IntPtr hObject
        );

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool RevertToSelf();


        // for unicode detection
        [Flags]
        public enum IsTextUnicodeFlags : int
        {
            IS_TEXT_UNICODE_ASCII16 = 0x0001,
            IS_TEXT_UNICODE_REVERSE_ASCII16 = 0x0010,

            IS_TEXT_UNICODE_STATISTICS = 0x0002,
            IS_TEXT_UNICODE_REVERSE_STATISTICS = 0x0020,

            IS_TEXT_UNICODE_CONTROLS = 0x0004,
            IS_TEXT_UNICODE_REVERSE_CONTROLS = 0x0040,

            IS_TEXT_UNICODE_SIGNATURE = 0x0008,
            IS_TEXT_UNICODE_REVERSE_SIGNATURE = 0x0080,

            IS_TEXT_UNICODE_ILLEGAL_CHARS = 0x0100,
            IS_TEXT_UNICODE_ODD_LENGTH = 0x0200,
            IS_TEXT_UNICODE_DBCS_LEADBYTE = 0x0400,
            IS_TEXT_UNICODE_NULL_BYTES = 0x1000,

            IS_TEXT_UNICODE_UNICODE_MASK = 0x000F,
            IS_TEXT_UNICODE_REVERSE_MASK = 0x00F0,
            IS_TEXT_UNICODE_NOT_UNICODE_MASK = 0x0F00,
            IS_TEXT_UNICODE_NOT_ASCII_MASK = 0xF000
        }

        [DllImport("Advapi32", SetLastError = false)]
        public static extern bool IsTextUnicode(
            byte[] buf,
            int len,
            ref IsTextUnicodeFlags opt
        );


        // for LSA Secrets Dump
        [DllImport("advapi32.dll", CharSet = CharSet.Auto)]
        public static extern int RegOpenKeyEx(
            uint hKey,
            string subKey,
            int ulOptions,
            int samDesired,
            ref IntPtr hkResult
        );

        [DllImport("advapi32.dll")]
        public static extern int RegQueryInfoKey(
            IntPtr hkey,
            StringBuilder lpClass,
            ref int lpcbClass,
            int lpReserved,
            ref IntPtr lpcSubKeys,
            ref IntPtr lpcbMaxSubKeyLen,
            ref IntPtr lpcbMaxClassLen,
            ref IntPtr lpcValues,
            ref IntPtr lpcbMaxValueNameLen,
            ref IntPtr lpcbMaxValueLen,
            ref IntPtr lpcbSecurityDescriptor,
            IntPtr lpftLastWriteTime
        );

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern int RegQueryValueEx(
            IntPtr hKey,
            string lpValueName,
            int lpReserved,
            IntPtr type,
            IntPtr lpData,
            ref int lpcbData
        );

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern int RegCloseKey(
            IntPtr hKey
        );


        [DllImport("shlwapi.dll", CharSet = CharSet.Unicode)]
        [return: MarshalAsAttribute(UnmanagedType.Bool)]
        internal static extern bool PathIsUNC([MarshalAsAttribute(UnmanagedType.LPWStr), In] string pszPath);


        // for DC enumeration
        [DllImport("Netapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern int DsGetDcName
          (
            [MarshalAs(UnmanagedType.LPTStr)] string ComputerName,
            [MarshalAs(UnmanagedType.LPTStr)] string DomainName,
            [In] int DomainGuid,
            [MarshalAs(UnmanagedType.LPTStr)] string SiteName,
            [MarshalAs(UnmanagedType.U4)] DSGETDCNAME_FLAGS flags,
            out IntPtr pDOMAIN_CONTROLLER_INFO
          );

        [DllImport("Netapi32.dll", SetLastError = true)]
        public  static extern int NetApiBufferFree(IntPtr Buffer);


        public static string GetDCName()
        {
            // retrieves the current domain controller name
            // adapted from https://www.pinvoke.net/default.aspx/netapi32.dsgetdcname
            DOMAIN_CONTROLLER_INFO domainInfo;
            const int ERROR_SUCCESS = 0;
            IntPtr pDCI = IntPtr.Zero;

            int val = DsGetDcName("", "", 0, "",
            DSGETDCNAME_FLAGS.DS_DIRECTORY_SERVICE_REQUIRED |
            DSGETDCNAME_FLAGS.DS_RETURN_DNS_NAME |
            DSGETDCNAME_FLAGS.DS_IP_REQUIRED, out pDCI);

            if (ERROR_SUCCESS == val)
            {
                domainInfo = (DOMAIN_CONTROLLER_INFO)Marshal.PtrToStructure(pDCI, typeof(DOMAIN_CONTROLLER_INFO));
                string dcName = domainInfo.DomainControllerName;
                NetApiBufferFree(pDCI);
                return dcName.Trim('\\');
            }
            else
            {
                string errorMessage = new Win32Exception((int)val).Message;
                Console.WriteLine("\r\n  [X] Error {0} retrieving domain controller : {1}", val, errorMessage);
                NetApiBufferFree(pDCI);
                return "";
            }
        }
    }
}