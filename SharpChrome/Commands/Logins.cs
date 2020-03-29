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
            Console.WriteLine("\r\n[*] Action: Chrome Saved Logins Triage\r\n");
            arguments.Remove("logins");

            string displayFormat = "csv";   // "csv" or "table" display
            string server = "";             // used for remote server specification
            bool showAll = false;           // whether to display entries with null passwords
            bool unprotect = false;         // whether to force CryptUnprotectData()

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

            if (arguments.ContainsKey("/server"))
            {
                server = arguments["/server"];
                Console.WriteLine("[*] Triaging remote server: {0}\r\n", server);
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
                Console.WriteLine("[*] Will decrypt user masterkeys with password: {0}\r\n", password);
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
                string target = arguments["/target"].Trim('"').Trim('\'');

                if (File.Exists(target))
                {
                    Console.WriteLine("[*] Target 'Login Data' File: {0}\r\n", target);
                    Chrome.ParseChromeLogins(masterkeys, target, displayFormat, showAll, unprotect);
                }
                else
                {
                    Console.WriteLine("\r\n[X] '{0}' is not a valid file.", target);
                }
            }
            else
            {
                if (arguments.ContainsKey("/server") && !arguments.ContainsKey("/pvk") && !arguments.ContainsKey("/password"))
                {
                    Console.WriteLine("[X] The '/server:X' argument must be used with '/pvk:BASE64...' or '/password:X' !");
                }
                else
                {
                    Chrome.TriageChromeLogins(masterkeys, server, displayFormat, showAll, unprotect);
                }
            }
        }
    }
}