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

            if (arguments.ContainsKey("/server") && !arguments.ContainsKey("/pvk") && !arguments.ContainsKey("/password"))
            {
                Console.WriteLine("[X] The '/server:X' argument must be used with '/pvk:BASE64...' or '/password:X' !");
            }
            else
            {
                Triage.TriageUserCreds(masterkeys, server);
                Triage.TriageUserVaults(masterkeys, server);
                Triage.TriageUserCerts(masterkeys, server);
                Console.WriteLine();
                if (masterkeys.Count == 0)
                {
                    // try to use CryptUnprotectData if no GUID lookups supplied
                    Triage.TriageRDCMan(masterkeys, server, true);
                }
                else
                {
                    Triage.TriageRDCMan(masterkeys, server, false);
                }
            }
        }
    }
}