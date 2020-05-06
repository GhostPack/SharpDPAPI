using System;
using System.Collections.Generic;


namespace SharpDPAPI.Commands
{

    public class Certificate : ICommand
    {
        public static string CommandName => "certificates";

        public void Execute(Dictionary<string, string> arguments)
        {
            Console.WriteLine("\r\n[*] Action: Cert Triage");
            arguments.Remove("cert");

            string server = "";             // used for remote server specification

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
            if (arguments.ContainsKey("/server"))
            {
                server = arguments["/server"];
                Console.WriteLine("[*] Triaging Certificates from remote server: {0}\r\n", server);
                Triage.TriageUserCerts(masterkeys, server);
            }

            if (arguments.ContainsKey("/target"))
            {
                string target = arguments["/target"].Trim('"').Trim('\'');

                Console.WriteLine("[*] Target Certificate File: {0}\r\n", target);
                Triage.TriageCertFile(target,masterkeys);
            }
            else
            {
                Triage.TriageUserCerts(masterkeys);
            }
          }
    }
}