using System;
using System.Collections.Generic;
using System.IO;

namespace SharpDPAPI.Commands
{
    public class Masterkeys : ICommand
    {
        public static string CommandName => "masterkeys";

        public void Execute(Dictionary<string, string> arguments)
        {
            Console.WriteLine("\r\n[*] Action: User DPAPI Masterkey File Triage\r\n");

            byte[] backupKeyBytes;
            string password;
            Dictionary<string, string> mappings = new Dictionary<string, string>();

            if (arguments.ContainsKey("/pvk"))
            {
                string pvk64 = arguments["/pvk"];
                if (File.Exists(pvk64))
                {
                    backupKeyBytes = File.ReadAllBytes(pvk64);
                }
                else
                {
                    backupKeyBytes = Convert.FromBase64String(pvk64);
                }
                if (arguments.ContainsKey("/server"))
                {
                    Console.WriteLine("[*] Triaging remote server: {0}\r\n", arguments["/server"]);
                    mappings = Triage.TriageUserMasterKeys(backupKeyBytes, true, arguments["/server"]);
                }
                else
                {
                    Console.WriteLine();
                    mappings = Triage.TriageUserMasterKeys(backupKeyBytes, true);
                }
            }
            else if (arguments.ContainsKey("/password"))
            {
                password = arguments["/password"];
                Console.WriteLine("[*] Will decrypt user masterkeys with password: {0}\r\n", password);
                if (arguments.ContainsKey("/server"))
                {
                    mappings = Triage.TriageUserMasterKeys(null, true, arguments["/server"], password);
                }
                else
                {
                    mappings = Triage.TriageUserMasterKeys(null, true, "", password);
                }
            }
            else
            {
                Console.WriteLine("[X] A /pvk:BASE64 domain DPAPI backup key or /password:X must be supplied!");
                return;
            }


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
        }
    }
}