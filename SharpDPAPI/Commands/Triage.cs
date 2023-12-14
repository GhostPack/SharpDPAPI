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

            string server = "";             // used for remote server specification

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

            if (arguments.ContainsKey("/server") && !arguments.ContainsKey("/pvk") && !arguments.ContainsKey("/password"))
            {
                Console.WriteLine("[X] The '/server:X' argument must be used with '/pvk:BASE64...' or '/password:X' !");
            }
            else
            {
                Triage.TriageUserCreds(masterkeys, server);
                Triage.TriageUserVaults(masterkeys, server);
                
                Console.WriteLine();
                if (masterkeys.Count == 0)
                {
                    // try to use CryptUnprotectData if no GUID lookups supplied
                    Triage.TriageRDCMan(masterkeys, server, true);
                    Triage.TriageKeePass(masterkeys, server, true);
                }
                else
                {
                    Triage.TriageRDCMan(masterkeys, server, false);
                    Triage.TriageKeePass(masterkeys, server, false);
                }

                Triage.TriageUserCerts(masterkeys, server, false);
            }
        }
    }
}