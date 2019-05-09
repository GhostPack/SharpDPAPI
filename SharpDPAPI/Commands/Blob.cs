using System;
using System.Collections.Generic;
using System.IO;

namespace SharpDPAPI.Commands
{
    public class Blob : ICommand
    {
        public static string CommandName => "blob";

        public void Execute(Dictionary<string, string> arguments)
        {
            Console.WriteLine("\r\n[*]  Action: Describe DPAPI blob\r\n");

            byte[] blobBytes;

            if (arguments.ContainsKey("/in"))
            {
                string blob = arguments["/in"];
                if (File.Exists(blob))
                {
                    blobBytes = File.ReadAllBytes(blob);
                }
                else
                {
                    blobBytes = Convert.FromBase64String(blob);
                }
                arguments.Remove("in");
            }
            else
            {
                Console.WriteLine("[X] An /in:<BASE64 | file> must be supplied!");
                return;
            }

            if (arguments.ContainsKey("/pvk"))
            {
                // using a domain backup key to decrypt everything

                string pvk64 = arguments["/pvk"];

                byte[] backupKeyBytes;

                if (File.Exists(pvk64))
                {
                    backupKeyBytes = File.ReadAllBytes(pvk64);
                }
                else
                {
                    backupKeyBytes = Convert.FromBase64String(pvk64);
                }

                Console.WriteLine("[*] Using a domain DPAPI backup key to triage masterkeys for decryption key mappings!");

                // build a {GUID}:SHA1 masterkey mappings
                Dictionary<string, string> mappings = new Dictionary<string, string>();

                mappings = Triage.TriageUserMasterKeys(backupKeyBytes, false);

                if (mappings.Count == 0)
                {
                    Console.WriteLine("[!] No master keys decrypted!\r\n");
                }
                else
                {
                    Console.WriteLine("[*] User master key cache:\r\n");
                    foreach (KeyValuePair<string, string> kvp in mappings)
                    {
                        Console.WriteLine("{0}:{1}", kvp.Key, kvp.Value);
                    }
                    Console.WriteLine();
                }

                byte[] decBytes = Dpapi.DescribeDPAPIBlob(blobBytes, mappings, "blob");

                if (decBytes.Length != 0)
                {
                    if (Helpers.IsUnicode(decBytes))
                    {
                        Console.WriteLine("    dec(blob)        : {0}", System.Text.Encoding.Unicode.GetString(decBytes));
                    }
                    else
                    {
                        string b64DecBytesString = BitConverter.ToString(decBytes).Replace("-", " ");
                        Console.WriteLine("    dec(blob)        : {0}", b64DecBytesString);
                    }
                }
            }
            else
            {
                byte[] decBytes = Dpapi.DescribeDPAPIBlob(blobBytes, arguments, "blob");

                if (decBytes.Length != 0)
                {
                    if (Helpers.IsUnicode(decBytes))
                    {
                        Console.WriteLine("    dec(blob)        : {0}", System.Text.Encoding.Unicode.GetString(decBytes));
                    }
                    else
                    {
                        string b64DecBytesString = BitConverter.ToString(decBytes).Replace("-", " ");
                        Console.WriteLine("    dec(blob)        : {0}", b64DecBytesString);
                    }
                }
            }
        }
    }
}