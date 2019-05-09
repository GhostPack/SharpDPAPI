using System;
using System.Collections.Generic;
using System.IO;

namespace SharpDPAPI.Commands
{
    public class RDG : ICommand
    {
        public static string CommandName => "rdg";

        public void Execute(Dictionary<string, string> arguments)
        {
            Console.WriteLine("\r\n[*] Action: RDG Triage\r\n");
            arguments.Remove("rdg");

            // whether to use CryptUnprotectData() instead of masterkeys
            bool unprotect = false;

            if (arguments.ContainsKey("/unprotect"))
            {
                unprotect = true;
                arguments.Remove("/unprotect");

                Console.WriteLine("[*] Using CryptUnprotectData() to decrypt RDG passwords\r\n");

                if (arguments.ContainsKey("/server")) {
                    Console.WriteLine("[X] The '/server:X' argument must be used with '/pvk:BASE64...' !");
                    return;
                }
            }

            if (arguments.ContainsKey("/target"))
            {
                string target = arguments["/target"];
                arguments.Remove("/target");

                if (arguments.ContainsKey("/pvk"))
                {
                    // using a domain backup key to decrypt everything
                    string pvk64 = arguments["/pvk"];
                    byte[] backupKeyBytes;

                    if (File.Exists(pvk64))
                    {
                        backupKeyBytes = File.ReadAllBytes(pvk64);
                    }
                    else
                    {
                        backupKeyBytes = Convert.FromBase64String(pvk64);
                    }

                    // build a {GUID}:SHA1 masterkey mappings
                    Dictionary<string, string> mappings = Triage.TriageUserMasterKeys(backupKeyBytes, false);

                    if (mappings.Count == 0)
                    {
                        Console.WriteLine("\r\n[!] No master keys decrypted!\r\n");
                    }
                    else
                    {
                        Console.WriteLine("\r\n[*] User master key cache:\r\n");
                        foreach (KeyValuePair<string, string> kvp in mappings)
                        {
                            Console.WriteLine("{0}:{1}", kvp.Key, kvp.Value);
                        }
                    }

                    Console.WriteLine("\r\n[*] Using a domain DPAPI backup key to triage masterkeys for decryption key mappings!\r\n");
                    arguments = mappings;
                }

                if (File.Exists(target))
                {
                    if (target.EndsWith(".rdg"))
                    {
                        Console.WriteLine("[*] Target .RDG File: {0}\r\n", target);
                        Triage.TriageRDGFile(arguments, target, unprotect);
                    }
                    else if (target.EndsWith(".settings"))
                    {
                        Console.WriteLine("[*] Target RDCMan.settings File: {0}\r\n", target);
                        Triage.TriageRDCManFile(arguments, target, unprotect);
                    }
                    else
                    {
                        Console.WriteLine("[X] Target must be .RDG or RDCMan.settings file: {0}\r\n", target);
                    }
                }
                else if (Directory.Exists(target))
                {
                    Console.WriteLine("[*] Target RDG Folder: {0}\r\n", target);
                    Triage.TriageRDGFolder(arguments, target, unprotect);
                }
                else
                {
                    Console.WriteLine("\r\n[X] '{0}' is not a valid file or directory.", target);
                }
            }

            else if (arguments.ContainsKey("/pvk"))
            {
                // using a domain backup key to decrypt everything

                string pvk64 = arguments["/pvk"];
                string server = "";

                byte[] backupKeyBytes;

                if (File.Exists(pvk64))
                {
                    backupKeyBytes = File.ReadAllBytes(pvk64);
                }
                else
                {
                    backupKeyBytes = Convert.FromBase64String(pvk64);
                }

                Console.WriteLine("[*] Using a domain DPAPI backup key to triage masterkeys for decryption key mappings!");

                // build a {GUID}:SHA1 masterkey mappings
                Dictionary<string, string> mappings = new Dictionary<string, string>();

                if (arguments.ContainsKey("/server"))
                {
                    server = arguments["/server"];
                    Console.WriteLine("[*] Triaging remote server: {0}\r\n", server);
                    mappings = Triage.TriageUserMasterKeys(backupKeyBytes, false, server);
                }
                else
                {
                    Console.WriteLine("");
                    mappings = Triage.TriageUserMasterKeys(backupKeyBytes, false);
                }

                if (mappings.Count == 0)
                {
                    Console.WriteLine("[!] No master keys decrypted!\r\n");
                }
                else
                {
                    Console.WriteLine("[*] User master key cache:\r\n");
                    foreach (KeyValuePair<string, string> kvp in mappings)
                    {
                        Console.WriteLine("{0}:{1}", kvp.Key, kvp.Value);
                    }
                    Console.WriteLine();
                }

                Triage.TriageRDCMan(mappings, server, unprotect);
            }
            else
            {
                if (arguments.ContainsKey("/server"))
                {
                    //Console.WriteLine("[X] The '/server:X' argument must be used with '/pvk:BASE64...' !");
                    Console.WriteLine("[X] /server:X option not currently supported for this function!");
                }
                else
                {
                    Triage.TriageRDCMan(arguments, "", unprotect);
                }
            }
        }
    }
}