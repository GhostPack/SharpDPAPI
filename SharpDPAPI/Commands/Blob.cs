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

            if (arguments.ContainsKey("/target"))
            {
                string blob = arguments["/target"].Trim('"').Trim('\'');
                if (File.Exists(blob))
                {
                    blobBytes = File.ReadAllBytes(blob);
                }
                else
                {
                    blobBytes = Convert.FromBase64String(blob);
                }
            }
            else
            {
                Console.WriteLine("[X] A /target:<BASE64 | file.bin> must be supplied!");
                return;
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

            byte[] decBytes = Dpapi.DescribeDPAPIBlob(blobBytes, masterkeys, "blob");

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