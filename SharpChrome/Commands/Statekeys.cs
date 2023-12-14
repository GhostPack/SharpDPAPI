using System;
using System.Collections.Generic;
using System.IO;

namespace SharpChrome.Commands
{
    public class Statekeys : ICommand
    {
        public static string CommandName => "statekeys";

        public void Execute(Dictionary<string, string> arguments)
        {
            Console.WriteLine("\r\n[*] Action: Chromium Statekey Extraction\r\n");
            arguments.Remove("statekeys");

            string server = "";             // used for remote server specification
            bool unprotect = false;         // whether to force CryptUnprotectData()

            if (arguments.ContainsKey("/unprotect"))
            {
                unprotect = true;
            }

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
                masterkeys = SharpDPAPI.Triage.TriageUserMasterKeys(show: true, computerName: server, password: arguments["/password"]);
            }
            else if (arguments.ContainsKey("/ntlm"))
            {
                Console.WriteLine("[*] Will decrypt user masterkeys with NTLM hash: {0}\r\n", arguments["/ntlm"]);
                masterkeys = SharpDPAPI.Triage.TriageUserMasterKeys(show: true, computerName: server, ntlm: arguments["/ntlm"]);
            }
            else if (arguments.ContainsKey("/credkey"))
            {
                Console.WriteLine("[*] Will decrypt user masterkeys with credkey: {0}\r\n", arguments["/credkey"]);
                masterkeys = SharpDPAPI.Triage.TriageUserMasterKeys(show: true, computerName: server, credkey: arguments["/credkey"]);
            }
            else if (arguments.ContainsKey("/rpc"))
            {
                Console.WriteLine("[*] Will ask a domain controller to decrypt masterkeys for us\r\n");
                masterkeys = SharpDPAPI.Triage.TriageUserMasterKeys(show: true, rpc: true);
            }

            if (arguments.ContainsKey("/target"))
            {
                string target = arguments["/target"].Trim('"').Trim('\'');

                if (File.Exists(target))
                {
                    Chrome.TriageStateKeys(masterkeys, server, unprotect, target);
                }
                else if (Directory.Exists(target) && target.ToLower().Contains("users"))
                {
                    Chrome.TriageStateKeys(masterkeys, server, unprotect, "", target);
                }
                else
                {
                    Console.WriteLine("\r\n[X] '{0}' is not a valid file or user directory.", target);
                }
            }
            else
            {
                if (arguments.ContainsKey("/server") && (masterkeys.Count == 0))
                {
                    Console.WriteLine("[!] Warning: the '/server:X' argument must be used with '/pvk:BASE64...', '/password:X' , or masterkey specification for successful decryption!");
                }
                Chrome.TriageStateKeys(masterkeys, server, unprotect);
            }
        }
    }
}