﻿using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;

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
                
                Console.WriteLine("[*] Will decrypt user masterkeys with {0}: {1}\r\n",
                    Regex.IsMatch(password, @"^([a-f0-9]{32}|[a-f0-9]{40})$", RegexOptions.IgnoreCase)
                        ? "hash" : "password", password);

                if (arguments.ContainsKey("/server"))
                {
                    masterkeys = Triage.TriageUserMasterKeys(null, true, arguments["/server"], password);
                }
                else
                {
                    masterkeys = Triage.TriageUserMasterKeys(null, true, "", password);
                }
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