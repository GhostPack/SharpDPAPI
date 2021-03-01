using System;
using System.Collections.Generic;
using System.IO;

namespace SharpDPAPI.Commands
{
    public class Keepass : ICommand
    {
        public static string CommandName => "keepass";

        public void Execute(Dictionary<string, string> arguments)
        {
            Console.WriteLine("\r\n[*] Action: KeePass Triage");
            arguments.Remove("keepass");

            string server = "";             // used for remote server specification
            bool unprotect = false;         // whether to force CryptUnprotectData()

            if (arguments.ContainsKey("/unprotect"))
            {
                Console.WriteLine("\r\n[*] Using CryptUnprotectData() for decryption.");
                unprotect = true;
            }
            Console.WriteLine("");

            if (arguments.ContainsKey("/server"))
            {
                server = arguments["/server"];
                Console.WriteLine("[*] Triaging remote server: {0}\r\n", server);
            }

            // {GUID}:SHA1 keys are the only ones that don't start with /
            Dictionary<string, string> masterkeys = new Dictionary<string, string>();
            foreach (KeyValuePair<string, string> entry in arguments)
            {
                if (!entry.Key.StartsWith("/"))
                {
                    masterkeys.Add(entry.Key, entry.Value);
                }
            }
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
                string password = arguments["/password"];
                Console.WriteLine("[*] Will decrypt user masterkeys with password: {0}\r\n", password);
                if (arguments.ContainsKey("/server"))
                {
                    masterkeys = Triage.TriageUserMasterKeys(null, true, arguments["/server"], password);
                }
                else
                {
                    masterkeys = Triage.TriageUserMasterKeys(null, true, "", password);
                }
            }

            if (arguments.ContainsKey("/target"))
            {
                string target = arguments["/target"].Trim('"').Trim('\'');

                if (target.EndsWith("ProtectedUserKey.bin"))
                {
                    Console.WriteLine("[*] Target ProtectedUserKey.bin File: {0}\r\n", target);
                    Triage.TriageKeePassKeyFile(masterkeys, target, unprotect);
                }
                else
                {
                    Console.WriteLine("[X] Target must be a ProtectedUserKey.bin file: {0}\r\n", target);
                }
            }
            else
            {
                if (arguments.ContainsKey("/server") && !arguments.ContainsKey("/pvk") && !arguments.ContainsKey("/password"))
                {
                    Console.WriteLine("[X] The '/server:X' argument must be used with '/pvk:BASE64...' or '/password:X' !");
                }
                else
                {
                    Triage.TriageKeePass(masterkeys, server, unprotect);
                }
            }
        }
    }
}