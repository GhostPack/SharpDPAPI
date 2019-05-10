using System;
using System.Collections.Generic;
using System.IO;

namespace SharpDPAPI.Commands
{
    public class UserTriage : ICommand
    {
        public static string CommandName => "triage";

        public void Execute(Dictionary<string, string> arguments)
        {
            Console.WriteLine("\r\n[*] Action: User DPAPI Credential and Vault Triage\r\n");
            arguments.Remove("triage");

            string server = "";

            if (arguments.ContainsKey("/pvk"))
            {
                // using a domain backup key to decrypt everything
                string pvk64 = arguments["/pvk"];
                byte[] backupKeyBytes = Convert.FromBase64String(pvk64);

                Console.WriteLine("[*] Using a domain DPAPI backup key to triage masterkeys for decryption key mappings!");

                // build a {GUID}:SHA1 masterkey mappings
                Dictionary<string, string> mappings = new Dictionary<string, string>();

                if (arguments.ContainsKey("/server"))
                {
                    // triage a remote server for masterkeys using the /pvk dpapi backup key
                    server = arguments["/server"];
                    Console.WriteLine("[*] Triaging remote server: {0}\r\n", server);
                    mappings = Triage.TriageUserMasterKeys(backupKeyBytes, false, server);
                }
                else
                {
                    // triage a local server for masterkeys using the /pvk dpapi backup key
                    Console.WriteLine("");
                    mappings = Triage.TriageUserMasterKeys(backupKeyBytes, false);
                }

                if (mappings.Count == 0)
                {
                    Console.WriteLine("[!] No master keys decrypted!\r\n");
                }
                else
                {
                    Console.WriteLine("[*] Master key cache:\r\n");
                    foreach (KeyValuePair<string, string> kvp in mappings)
                    {
                        Console.WriteLine("{0}:{1}", kvp.Key, kvp.Value);
                    }
                    Console.WriteLine();
                }

                Triage.TriageUserCreds(mappings, server);
                Triage.TriageUserVaults(mappings, server);
                Console.WriteLine();
                Triage.TriageRDCMan(mappings, server, false);

                return;
            }
            else
            {
                if (arguments.ContainsKey("/server"))
                {
                    Console.WriteLine("[X] The '/server:X' argument must be used with '/pvk:BASE64...' !");
                    return;
                }
                else
                {
                    Triage.TriageUserCreds(arguments);
                    Triage.TriageUserVaults(arguments);
                    Console.WriteLine();
                    if(arguments.Count == 0)
                    {
                        // try to use CryptUnprotectData if no GUID lookups supplied
                        Triage.TriageRDCMan(arguments, "", true);
                    }
                    else
                    {
                        Triage.TriageRDCMan(arguments, "", false);
                    }
                }
            }
        }
    }
}