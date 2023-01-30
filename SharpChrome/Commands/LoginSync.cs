using System;
using System.Collections.Generic;
using System.IO;

namespace SharpChrome.Commands
{
    /// <summary>
    /// Copy logins from Chrome to edge.
    /// </summary>
    public class LoginSync : ICommand
    {
        public static string CommandName => nameof(LoginSync).ToLower();

        public void Execute(Dictionary<string, string> arguments)
        {
            arguments.Remove(CommandName);

            string displayFormat = "csv"; // "csv" or "table" display
            string server = ""; // used for remote server specification
            bool showAll = false; // whether to display entries with null passwords
            bool unprotect = false; // whether to force CryptUnprotectData()
            bool quiet = false; // don't display headers/logos/etc. (for csv/json output)
            string stateKey = ""; // decrypted AES statekey to use for cookie decryption
            string browser = "chrome"; // alternate Chromiun browser to specify, currently supported: "chrome", "edge", "brave"
            string target = ""; // target file/user folder to triage
            
            // {GUID}:SHA1 keys are the only ones that don't start with /
            Dictionary<string, string> masterkeys = new Dictionary<string, string>();
            foreach (KeyValuePair<string, string> entry in arguments) {
                if (!entry.Key.StartsWith("/")) {
                    masterkeys.Add(entry.Key, entry.Value);
                }
            }
            
            Chrome.TriageAndReturnChromeLogins(masterkeys, server, target, displayFormat, showAll, unprotect, stateKey, browser, quiet);
        }
    }
}