﻿using System;
using System.Collections.Generic;
using System.IO;

namespace SharpDPAPI.Commands
{
    public class Credentials : ICommand
    {
        public static string CommandName => "credentials";

        public void Execute(Dictionary<string, string> arguments)
        {
            Console.WriteLine("\r\n[*] Action: User DPAPI Credential Triage\r\n");
            arguments.Remove("credentials");

            Dictionary<string, string> masterkeys = new Dictionary<string, string>();
            string server = "";             // used for remote server specification
            string password = "";

            if (arguments.ContainsKey("/server"))
            {
                server = arguments["/server"];
                Console.WriteLine("[*] Triaging remote server: {0}\r\n", server);
            }
            if (arguments.ContainsKey("/password"))
            {
                password = arguments["/password"];
                Console.WriteLine("[*] Will decrypt credentials with user password: {0}\r\n", password);
                masterkeys = Triage.TriageUserMasterKeysWithPass(password);
            }

            // {GUID}:SHA1 keys are the only ones that don't start with /
            
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

            if (arguments.ContainsKey("/target"))
            {
                string target = arguments["/target"].Trim('"').Trim('\'');

                if (File.Exists(target))
                {
                    Console.WriteLine("[*] Target Credential File: {0}\r\n", target);
                    Triage.TriageCredFile(target, masterkeys);
                }
                else if (Directory.Exists(target))
                {
                    Console.WriteLine("[*] Target Credential Folder: {0}\r\n", target);
                    Triage.TriageCredFolder(target, masterkeys);
                }
                else
                {
                    Console.WriteLine("\r\n[X] '{0}' is not a valid file or directory.", target);
                }
            }
            else
            {
                if (arguments.ContainsKey("/server") && !arguments.ContainsKey("/pvk"))
                {
                    Console.WriteLine("[X] The '/server:X' argument must be used with '/pvk:BASE64...' !");
                }
                else
                {
                    Triage.TriageUserCreds(masterkeys, server);
                }
            }
        }
    }
}