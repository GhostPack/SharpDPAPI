using System;
using System.Collections.Generic;
using System.IO;

namespace SharpDPAPI.Commands
{
    public class Machinetriage : ICommand
    {
        public static string CommandName => "machinetriage";

        public void Execute(Dictionary<string, string> arguments)
        {
            Console.WriteLine("\r\n[*] Action: Machine DPAPI Credential, Vault, and Certificate Triage\r\n");
            arguments.Remove("triage");


            if (!Helpers.IsHighIntegrity())
            {
                Console.WriteLine("[X] Must be elevated to triage SYSTEM DPAPI Credentials!");
            }
            else
            {
                Dictionary<string, string> mappings = Triage.TriageSystemMasterKeys();

                Console.WriteLine("\r\n[*] SYSTEM master key cache:\r\n");
                foreach (KeyValuePair<string, string> kvp in mappings)
                {
                    Console.WriteLine("{0}:{1}", kvp.Key, kvp.Value);
                }
                Console.WriteLine();

                Triage.TriageSystemCreds(mappings);
                Triage.TriageSystemVaults(mappings);
                Triage.TriageSystemCerts(mappings);
            }
        }
    }
}