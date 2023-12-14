using System;
using System.Collections.Generic;
using System.DirectoryServices.ActiveDirectory;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
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

            byte[] backupKeyBytes = null;
            string password = "";
            string ntlm = "";
            string credkey = "";
            string computerName = "";
            string target = "";
            string sid = "";
            bool hashes = false;        // true to display the matserkeys as hashes
            bool rpc = false;           // true to use RPC MS-BKUP for retrieval
            bool show = true;           // true to show the masterkey results in the Triage code 
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
            }

            if (arguments.ContainsKey("/server"))
            {
                computerName = arguments["/server"];
            }
            if (arguments.ContainsKey("/target"))
            {
                target = arguments["/target"];
            }

            if (arguments.ContainsKey("/password"))
            {
                password = arguments["/password"];
            }
            if (arguments.ContainsKey("/ntlm"))
            {
                ntlm = arguments["/ntlm"];
            }
            if (arguments.ContainsKey("/credkey"))
            {
                credkey = arguments["/credkey"];
            }
            if (arguments.ContainsKey("/sid"))
            {
                sid = arguments["/sid"];
            }

            if (arguments.ContainsKey("/hashes"))
            {
                hashes = true;
            }
            if (arguments.ContainsKey("/rpc"))
            {
                rpc = true;
            }

            if (
                (arguments.ContainsKey("/password") || arguments.ContainsKey("/ntlm") || arguments.ContainsKey("/credkey")) 
                && arguments.ContainsKey("/target")
                && !arguments.ContainsKey("/sid"))
            {
                Console.WriteLine("[X] When using /password, /ntlm, or /credkey with /target:X, a /sid:X (domain user SID) is required!");
                return;
            }

            if (arguments.ContainsKey("/hashes") && arguments.ContainsKey("/target") && !arguments.ContainsKey("/sid"))
            {
                Console.WriteLine("[X] When using /password, /ntlm, or /credkey with /target:X, a /sid:X (domain user SID) is required!");
                return;
            }

            if (
                !(arguments.ContainsKey("/password") || arguments.ContainsKey("/ntlm") || arguments.ContainsKey("/credkey"))
                && !arguments.ContainsKey("/pvk")
                && !arguments.ContainsKey("/rpc")
                && !arguments.ContainsKey("/hashes"))
            {
                Console.WriteLine("[X] A /pvk:BASE64 domain DPAPI backup key, /rpc, /password, /ntlm, /credkey, or /hashes must be supplied!");
                return;
            }

            mappings = Triage.TriageUserMasterKeys( backupKeyBytes: backupKeyBytes, show: show, computerName: computerName,
                                                    password: password, ntlm: ntlm, credkey: credkey, target: target,
                                                    userSID: sid, dumpHash: hashes, rpc: rpc);
        }
    }
}