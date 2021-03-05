using System;
using System.Collections.Generic;
using System.IO;

namespace SharpChrome.Commands
{
    public class Logins : ICommand
    {
        public static string CommandName => "logins";

        public void Execute(Dictionary<string, string> arguments)
        {
            arguments.Remove("logins");

            string displayFormat = "csv";   // "csv" or "table" display
            string server = "";             // used for remote server specification
            bool showAll = false;           // whether to display entries with null passwords
            bool unprotect = false;         // whether to force CryptUnprotectData()
            bool quiet = false;             // don't display headers/logos/etc. (for csv/json output)
            string stateKey = "";           // decrypted AES statekey to use for cookie decryption
            string browser = "chrome";      // alternate Chromiun browser to specify, currently supported: "chrome", "edge", "brave"
            string target = "";             // target file/user folder to triage


            if (arguments.ContainsKey("/quiet"))
            {
                quiet = true;
            }

            if (arguments.ContainsKey("/browser"))
            {
                browser = arguments["/browser"].ToLower();
            }

            if (!quiet)
            {
                Console.WriteLine("\r\n[*] Action: {0} Saved Logins Triage\r\n", SharpDPAPI.Helpers.Capitalize(browser));
            }

            if (arguments.ContainsKey("/format"))
            {
                displayFormat = arguments["/format"];
            }

            if (arguments.ContainsKey("/unprotect"))
            {
                unprotect = true;
            }

            if (arguments.ContainsKey("/showall"))
            {
                showAll = true;
            }

            if (arguments.ContainsKey("/statekey"))
            {
                stateKey = arguments["/statekey"];
                if (!quiet)
                {
                    Console.WriteLine("[*] Using AES State Key: {0}]\r\n", stateKey);
                }
            }

            if (arguments.ContainsKey("/server"))
            {
                server = arguments["/server"];
                if (!quiet)
                {
                    Console.WriteLine("[*] Triaging remote server: {0}\r\n", server);
                }
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
                if (!quiet)
                {
                    Console.WriteLine("[*] Will decrypt user masterkeys with password: {0}\r\n", password);
                }
                if (arguments.ContainsKey("/server"))
                {
                    masterkeys = SharpDPAPI.Triage.TriageUserMasterKeys(null, true, arguments["/server"], password);
                }
                else
                {
                    masterkeys = SharpDPAPI.Triage.TriageUserMasterKeys(null, true, "", password);
                }
            }

            if (arguments.ContainsKey("/target"))
            {
                target = arguments["/target"].Trim('"').Trim('\'');
                byte[] stateKeyBytes = null;

                if (!String.IsNullOrEmpty(stateKey))
                {
                    stateKeyBytes = SharpDPAPI.Helpers.ConvertHexStringToByteArray(stateKey);
                }

                if (File.Exists(target))
                {
                    if (!quiet)
                    {
                        Console.WriteLine("[*] Target 'Login Data' File: {0}\r\n", target);
                    }
                    Chrome.ParseChromeLogins(masterkeys, target, displayFormat, showAll, unprotect, stateKeyBytes, quiet);
                }
                else if(Directory.Exists(target) && target.ToLower().Contains("users"))
                {
                    Chrome.TriageChromeLogins(masterkeys, server, target, displayFormat, showAll, unprotect, stateKey, browser, quiet);
                }
                else
                {
                    Console.WriteLine("\r\n[X] '{0}' is not a valid file or user directory.", target);
                }
            }
            else
            {
                if (arguments.ContainsKey("/server") && (masterkeys.Count == 0))
                {
                    Console.WriteLine("[!] Warning: the '/server:X' argument must be used with '/pvk:BASE64...', '/password:X' , or masterkey specification for successful decryption!");
                }
                
                Chrome.TriageChromeLogins(masterkeys, server, target, displayFormat, showAll, unprotect, stateKey, browser, quiet);
            }
        }
    }
}