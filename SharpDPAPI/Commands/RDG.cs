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
            Console.WriteLine("\r\n[*] Action: RDG Triage");
            arguments.Remove("rdg");

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
                Console.WriteLine("[*] Will decrypt user masterkeys with password: {0}\r\n", arguments["/password"]);
                masterkeys = Triage.TriageUserMasterKeys(show: true, computerName: server, password: arguments["/password"]);
            }
            else if (arguments.ContainsKey("/ntlm"))
            {
                Console.WriteLine("[*] Will decrypt user masterkeys with NTLM hash: {0}\r\n", arguments["/ntlm"]);
                masterkeys = Triage.TriageUserMasterKeys(show: true, computerName: server, ntlm: arguments["/ntlm"]);
            }
            else if (arguments.ContainsKey("/prekey"))
            {
                Console.WriteLine("[*] Will decrypt user masterkeys with PreKey: {0}\r\n", arguments["/prekey"]);
                masterkeys = Triage.TriageUserMasterKeys(show: true, computerName: server, prekey: arguments["/prekey"]);
            }
            else if (arguments.ContainsKey("/rpc"))
            {
                Console.WriteLine("[*] Will ask a domain controller to decrypt masterkeys for us\r\n");
                masterkeys = Triage.TriageUserMasterKeys(show: true, rpc: true);
            }

            if (arguments.ContainsKey("/target"))
            {
                string target = arguments["/target"].Trim('"').Trim('\'');

                if (target.EndsWith(".rdg"))
                {
                    Console.WriteLine("[*] Target .RDG File: {0}\r\n", target);
                    Triage.TriageRDGFile(masterkeys, target, unprotect);
                }
                else if (target.EndsWith(".settings"))
                {
                    Console.WriteLine("[*] Target RDCMan.settings File: {0}\r\n", target);
                    Triage.TriageRDCManFile(masterkeys, target, unprotect);
                }
                else
                {
                    Console.WriteLine("[X] Target must be .RDG or RDCMan.settings file: {0}\r\n", target);
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
                    Triage.TriageRDCMan(masterkeys, server, unprotect);
                }
            }
        }
    }
}