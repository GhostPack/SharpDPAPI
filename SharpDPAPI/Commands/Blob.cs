using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace SharpDPAPI.Commands
{
    public class Blob : ICommand
    {
        public static string CommandName => "blob";

        public void Execute(Dictionary<string, string> arguments)
        {
            Console.WriteLine("\r\n[*] Action: Describe DPAPI blob");

            byte[] blobBytes;
            bool unprotect = false;         // whether to force CryptUnprotectData()
            byte[] entropy = null;
            var server = "";

            if (arguments.ContainsKey("/unprotect"))
            {
                Console.WriteLine("\r\n[*] Using CryptUnprotectData() for decryption.");
                unprotect = true;
            }
            Console.WriteLine();

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

            if (arguments.ContainsKey("/server"))
            {
                server = arguments["/server"];
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

            if (arguments.ContainsKey("/entropy"))
            {
                entropy = Helpers.ConvertHexStringToByteArray(arguments["/entropy"]);
            }

            if (blobBytes.Length > 0)
            {
                byte[] decBytesRaw = Dpapi.DescribeDPAPIBlob(blobBytes, masterkeys, "blob", unprotect, entropy);

                if ((decBytesRaw != null) && (decBytesRaw.Length != 0))
                {
                    if (Helpers.IsUnicode(decBytesRaw))
                    {
                        string data = "";
                        int finalIndex = Array.LastIndexOf(decBytesRaw, (byte)0);
                        if (finalIndex > 1)
                        {
                            byte[] decBytes = new byte[finalIndex + 1];
                            Array.Copy(decBytesRaw, 0, decBytes, 0, finalIndex);
                            data = Encoding.Unicode.GetString(decBytes);
                        }
                        else
                        {
                            data = Encoding.ASCII.GetString(decBytesRaw);
                        }
                        Console.WriteLine("    dec(blob)        : {0}", data);
                    }
                    else
                    {
                        string hexData = BitConverter.ToString(decBytesRaw).Replace("-", " ");
                        Console.WriteLine("    dec(blob)        : {0}", hexData);
                    }
                }
            }
        }
    }
}