using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using static SharpDPAPI.Crypto;

namespace SharpDPAPI.Commands
{
    public class Protect : ICommand
    {
        public static string CommandName => "protect";

        public void Execute(Dictionary<string, string> arguments)
        {
            Console.WriteLine("\r\n[*] Action: Encrypt DPAPI blob");

            if (!arguments.ContainsKey("/mkfile"))
            {
                Console.WriteLine("[!] Error: Provide a master key file using /mkfile:<path>");
                return;
            }

            if (!arguments.ContainsKey("/password"))
            {
                Console.WriteLine("[!] Error: Provide a password");
                return;
            }

            if (!arguments.ContainsKey("/input"))
            {
                Console.WriteLine("[!] Error: provide an input file path or base64 using /input:<file>");
                return;
            }

            if (!arguments.ContainsKey("/output"))
            {
                Console.WriteLine("[!] Error: provide an output file path using /output:<file>");
                return;
            }

            byte[] plainBytes;
            string inputFile = arguments["/input"].Trim('"').Trim('\'');
            string outputFile = arguments["/output"].Trim('"').Trim('\'');
            string masterKeyFile = arguments["/mkfile"].Trim('"').Trim('\'');
            string password = arguments["/password"];

            if (File.Exists(inputFile))
            {
                plainBytes = File.ReadAllBytes(inputFile);
            }
            else
            {
                plainBytes = Convert.FromBase64String(inputFile);
            }

            Console.WriteLine("[*] Using masterkey: {0}", masterKeyFile);
            
            string userSID = Dpapi.ExtractSidFromPath(masterKeyFile);
            
            var masterkeys = Triage.TriageUserMasterKeys(
                null, password: password, target: masterKeyFile,
                local: true, userSID: userSID
                );
            
            if (masterkeys.Count != 1)
            {
                Console.WriteLine("[!] Failed to decrypt masterkey. Wrong password?");
                return;
            }

            var masterKey = masterkeys.First();
            byte[] enc = Dpapi.CreateDPAPIBlob(plainBytes, Helpers.StringToByteArray(masterKey.Value),
                EncryptionAlgorithm.CALG_AES_256,
                HashAlgorithm.CALG_SHA_512,
                new Guid(masterKey.Key));

            File.WriteAllBytes(outputFile, enc);
            Console.WriteLine("[+] Done! Wrote {0} bytes to: {1}", enc.Length, outputFile);
        }
    }
}