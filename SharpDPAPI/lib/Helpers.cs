using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;

namespace SharpDPAPI
{
    public class Helpers
    {
        public static void EncodeLength(BinaryWriter stream, int length)
        {
            if (length < 0) throw new ArgumentOutOfRangeException("length", "Length must be non-negative");
            if (length < 0x80)
            {
                // Short form
                stream.Write((byte)length);
            }
            else
            {
                // Long form
                var temp = length;
                var bytesRequired = 0;
                while (temp > 0)
                {
                    temp >>= 8;
                    bytesRequired++;
                }
                stream.Write((byte)(bytesRequired | 0x80));
                for (var i = bytesRequired - 1; i >= 0; i--)
                {
                    stream.Write((byte)(length >> (8 * i) & 0xff));
                }
            }
        }
        public static void EncodeIntegerBigEndian(BinaryWriter stream, byte[] value, bool forceUnsigned = true)
        {
            stream.Write((byte)0x02); // INTEGER
            var prefixZeros = 0;
            for (var i = 0; i < value.Length; i++)
            {
                if (value[i] != 0) break;
                prefixZeros++;
            }

            if (value.Length - prefixZeros == 0)
            {
                EncodeLength(stream, 1);
                stream.Write((byte)0);
            }
            else
            {
                if (forceUnsigned && value[prefixZeros] > 0x7f)
                {
                    // Add a prefix zero to force unsigned if the MSB is 1
                    EncodeLength(stream, value.Length - prefixZeros + 1);
                    stream.Write((byte)0);
                }
                else
                {
                    EncodeLength(stream, value.Length - prefixZeros);
                }

                for (var i = prefixZeros; i < value.Length; i++)
                {
                    stream.Write(value[i]);
                }
            }
        }

        public static byte[] trimByte(byte[] input)
        {

            int byteCounter = input.Length - 1;
            while (input[byteCounter] == 0x00)
            {
                byteCounter--;
            }
            byte[] rv = new byte[(byteCounter + 1)];
            for (int byteCounter1 = 0; byteCounter1 < (byteCounter + 1); byteCounter1++)
            {
                rv[byteCounter1] = input[byteCounter1];
            }
            return rv;
        }

        public static BigInteger OS2IP(byte[] data, bool isLittleEndian)
        {
            BigInteger bi = 0;
            if (isLittleEndian)
            {
                for (int i = 0; i < data.Length; i++)
                {
                    bi += BigInteger.Pow(256, i) * (long)data[i];
                }
            }
            else
            {
                for (int i = 1; i <= data.Length; i++)
                {
                    bi += BigInteger.Pow(256, i - 1) * (long)data[data.Length - i];
                }
            }
            return bi;
        }

        public static byte[] ConvertHexStringToByteArray(string hexString)
        {
            if (hexString.Length % 2 != 0)
            {
                //throw new ArgumentException(String.Format("The binary key cannot have an odd number of digits: {0}", hexString));
                hexString = "0" + hexString;
            }

            byte[] HexAsBytes = new byte[hexString.Length / 2];
            for (int index = 0; index < HexAsBytes.Length; index++)
            {
                string byteValue = hexString.Substring(index * 2, 2);
                HexAsBytes[index] = byte.Parse(byteValue, System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture);
            }

            return HexAsBytes;
        }
        public static bool TestRemote(string computerName)
        {
            try
            {
                string remotePath = String.Format("\\\\{0}\\C$\\Users\\", computerName);
                string[] dirs = Directory.GetDirectories(remotePath);
                return true;
            }
            catch (Exception e)
            {
                Console.WriteLine("[!] Error accessing computer '{0}' : {1}", computerName, e.Message);
                return false;
            }
        }

        public static string ConvertLocalPathToUNCPath(string computerName, string localPath)
        {
            // takes a computername and local path, and returns a translated \\UNC path for that file
            try
            {
                string[] parts = localPath.Split(new char[] { System.IO.Path.DirectorySeparatorChar }, StringSplitOptions.RemoveEmptyEntries);
                string driveLetter = parts[0].Replace(':', '$');
                string newPath = String.Format("\\\\{0}\\{1}\\{2}", computerName, driveLetter, String.Join("\\", (parts.Skip(1).Take(parts.Length - 1)).ToArray()));
                return newPath;
            }
            catch
            {
                return "";
            }
        }

        public static byte[] Combine(byte[] first, byte[] second)
        {
            // helper to combine two byte arrays
            byte[] ret = new byte[first.Length + second.Length];
            Buffer.BlockCopy(first, 0, ret, 0, first.Length);
            Buffer.BlockCopy(second, 0, ret, first.Length, second.Length);
            return ret;
        }

        public static string[] Combine(string[] first, string[] second)
        {
            // helper to combine two string arrays
            string[] ret = new string[first.Length + second.Length];
            Array.Copy(first, 0, ret, 0, first.Length);
            Array.Copy(second, 0, ret, first.Length, second.Length);
            return ret;
        }

        public static bool IsUnicode(byte[] bytes)
        {
            // helper that users the IsTextUnicode() API call to determine if a byte array is likely unicode text
            Interop.IsTextUnicodeFlags flags = Interop.IsTextUnicodeFlags.IS_TEXT_UNICODE_STATISTICS;
            return Interop.IsTextUnicode(bytes, bytes.Length, ref flags);
        }

        public static string RemoveWhiteSpaces(string input)
        {
            return Regex.Replace(input, @"\ +(?=(\n|\r?$))", "");
        }

        public static string StringToCSVCell(string str)
        {
            // helper that cleans a string for CSV output
            bool mustQuote = (str.Contains(",") || str.Contains("\"") || str.Contains("\r") || str.Contains("\n"));
            if (mustQuote)
            {
                StringBuilder sb = new StringBuilder();
                sb.Append("\"");
                foreach (char nextChar in str)
                {
                    sb.Append(nextChar);
                    if (nextChar == '"')
                        sb.Append("\"");
                }
                sb.Append("\"");
                return sb.ToString();
            }
            return str;
        }
     
        public static string CleanForJSON(string s)
        {
            // helper that cleans a string for JSON output
            // https://stackoverflow.com/questions/1242118/how-to-escape-json-string/17691629#17691629

            if (s == null || s.Length == 0)
            {
                return "";
            }

            char c = '\0';
            int i;
            int len = s.Length;
            StringBuilder sb = new StringBuilder(len + 4);
            String t;

            for (i = 0; i < len; i += 1)
            {
                c = s[i];
                switch (c)
                {
                    case '\\':
                    case '"':
                        sb.Append('\\');
                        sb.Append(c);
                        break;
                    case '/':
                        sb.Append('\\');
                        sb.Append(c);
                        break;
                    case '\b':
                        sb.Append("\\b");
                        break;
                    case '\t':
                        sb.Append("\\t");
                        break;
                    case '\n':
                        sb.Append("\\n");
                        break;
                    case '\f':
                        sb.Append("\\f");
                        break;
                    case '\r':
                        sb.Append("\\r");
                        break;
                    default:
                        if (c < ' ')
                        {
                            t = "000" + String.Format("X", c);
                            sb.Append("\\u" + t.Substring(t.Length - 4));
                        }
                        else
                        {
                            sb.Append(c);
                        }
                        break;
                }
            }
            return sb.ToString();
        }

        public static DateTime ConvertToDateTime(string chromeTime)
        {
            // helper that converts Chrome's stupid timestamp format
            // https://stackoverflow.com/questions/20458406/what-is-the-format-of-chromes-timestamps
            // https://linuxsleuthing.blogspot.com/2011/06/decoding-google-chrome-timestamps-in.html
            DateTime epoch = new DateTime(1601, 1, 1);
            try
            {
                double dateCreatedRaw = double.Parse(chromeTime);
                double secsFromEpoch = dateCreatedRaw / 1000000;
                if (secsFromEpoch > TimeSpan.MaxValue.TotalSeconds)
                {
                    // handle timestamps over the allowed range
                    return new DateTime(DateTime.MaxValue.Ticks);
                }
                if (secsFromEpoch < 0)
                {
                    secsFromEpoch = 0;
                }
                return epoch.Add(TimeSpan.FromSeconds(secsFromEpoch)).ToLocalTime();
            }
            catch
            {
                // in case the parsing fails
                return epoch;
            }
        }

        public static Dictionary<string, string> ParseMasterKeyFile(string filePath)
        {
            // helper that parses a {GUID}:SHA1 masterkey file
            Dictionary<string, string> masterkeys = new Dictionary<string, string>();

            if (File.Exists(filePath))
            {
                string[] lines = File.ReadAllLines(filePath);
                try
                {
                    foreach (string line in lines)
                    {
                        string[] parts = line.Split(' '); // in case we have multiple keys on one line
                        foreach (string part in parts)
                        {
                            if (!String.IsNullOrEmpty(part.Trim()))
                            {
                                if (part.StartsWith("{"))
                                {
                                    // SharpDPAPI {GUID}:SHA1 format
                                    string[] mk = part.Split(':');
                                    if (!masterkeys.ContainsKey(mk[0]))
                                    {
                                        masterkeys.Add(mk[0], mk[1]);
                                    }
                                }
                                else if (part.StartsWith("GUID:"))
                                {
                                    // Mimikatz dpapi::cache format
                                    string[] mk = part.Split(';');
                                    string[] guid = mk[0].Split(':');
                                    string[] sha1 = mk[1].Split(':');
                                    if (!masterkeys.ContainsKey(guid[0]))
                                    {
                                        masterkeys.Add(guid[1], sha1[1]);
                                    }
                                }
                            }
                        }
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine("[X] Error parsing masterkey file '{0}' : {1}", filePath, e.Message);
                }
            }
            else
            {
                Console.WriteLine("[X] Masterkey file '{0}' doesn't exist!", filePath);
            }
            return masterkeys;
        }

        public static bool GetSystem()
        {
            // helper to elevate to SYSTEM via token impersonation
            //  used for LSA secret (DPAPI_SYSTEM) retrieval

            if (IsHighIntegrity())
            {
                IntPtr hToken = IntPtr.Zero;

                // Open winlogon's token with TOKEN_DUPLICATE accesss so ca can make a copy of the token with DuplicateToken
                Process[] processes = Process.GetProcessesByName("winlogon");
                IntPtr handle = processes[0].Handle;

                // TOKEN_DUPLICATE = 0x0002
                bool success = Interop.OpenProcessToken(handle, 0x0002, out hToken);
                if (!success)
                {
                    //Console.WriteLine("OpenProcessToken failed!");
                    return false;
                }

                // make a copy of the NT AUTHORITY\SYSTEM token from winlogon
                // 2 == SecurityImpersonation
                IntPtr hDupToken = IntPtr.Zero;
                success = Interop.DuplicateToken(hToken, 2, ref hDupToken);
                if (!success)
                {
                    //Console.WriteLine("DuplicateToken failed!");
                    return false;
                }

                success = Interop.ImpersonateLoggedOnUser(hDupToken);
                if (!success)
                {
                    //Console.WriteLine("ImpersonateLoggedOnUser failed!");
                    return false;
                }

                // clean up the handles we created
                Interop.CloseHandle(hToken);
                Interop.CloseHandle(hDupToken);

                string name = System.Security.Principal.WindowsIdentity.GetCurrent().Name;
                if (name != "NT AUTHORITY\\SYSTEM")
                {
                    return false;
                }

                return true;
            }
            else
            {
                return false;
            }
        }

        public static byte[] GetRegKeyValue(string keyPath)
        {
            // takes a given HKLM key path and returns the registry value

            int result = 0;
            IntPtr hKey = IntPtr.Zero;

            // open the specified key with read (0x19) privileges
            //  0x80000002 == HKLM
            result = Interop.RegOpenKeyEx(0x80000002, keyPath, 0, 0x19, ref hKey);
            if (result != 0)
            {
                int error = Marshal.GetLastWin32Error();
                string errorMessage = new Win32Exception((int)error).Message;
                Console.WriteLine("Error opening {0} ({1}) : {2}", keyPath, error, errorMessage);
                return null;
            }

            int cbData = 0;
            result = Interop.RegQueryValueEx(hKey, null, 0, IntPtr.Zero, IntPtr.Zero, ref cbData);
            if (result != 0)
            {
                int error = Marshal.GetLastWin32Error();
                string errorMessage = new Win32Exception((int)error).Message;
                Console.WriteLine("Error enumerating {0} ({1}) : {2}", keyPath, error, errorMessage);
                return null;
            }

            IntPtr dataPtr = Marshal.AllocHGlobal(cbData);
            result = Interop.RegQueryValueEx(hKey, null, 0, IntPtr.Zero, dataPtr, ref cbData);
            if (result != 0)
            {
                int error = Marshal.GetLastWin32Error();
                string errorMessage = new Win32Exception((int)error).Message;
                Console.WriteLine("Error enumerating {0} ({1}) : {2}", keyPath, error, errorMessage);
                return null;
            }
            byte[] data = new byte[cbData];

            Marshal.Copy(dataPtr, data, 0, cbData);
            Interop.RegCloseKey(hKey);

            return data;
        }

        public static byte[] StringToByteArray(string hex)
        {
            // helper to convert a string hex representation to a byte array
            // yes, I know this inefficient :)
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }

        public static IEnumerable<string> Split(string text, int partLength)
        {
            // helper to split strings into blobs of particular length

            if (text == null) { Console.WriteLine("[!] Split() - singleLineString"); }
            if (partLength < 1) { Console.WriteLine("[!] Split() - 'columns' must be greater than 0."); }

            var partCount = Math.Ceiling((double)text.Length / partLength);
            if (partCount < 2)
            {
                yield return text;
            }

            for (int i = 0; i < partCount; i++)
            {
                var index = i * partLength;
                var lengthLeft = Math.Min(partLength, text.Length - index);
                var line = text.Substring(index, lengthLeft);
                yield return line;
            }
        }

        public static bool IsHighIntegrity()
        {
            // returns true if the current process is running with adminstrative privs in a high integrity context

            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }

        public static bool ByteArrayEquals(byte[] sourceArray, int sourceIndex, byte[] destArray, int destIndex, int len)
        {
            int j = destIndex;
            for (int i = sourceIndex; i < sourceIndex + len; i++)
            {
                if (sourceArray[i] != destArray[j])
                    return false;
                j++;
            }
            return true;
        }

        public static int ArrayIndexOf(byte[] arrayToSearchThrough, byte[] patternToFind, int offset = 0)
        {
            // helper to search for byte array patterns in another byte array
            //  used to search for headers in decrypted policy blobs

            if (patternToFind.Length > arrayToSearchThrough.Length)
                return -1;
            for (int i = offset; i < arrayToSearchThrough.Length - patternToFind.Length; i++)
            {
                bool found = true;
                for (int j = 0; j < patternToFind.Length; j++)
                {
                    if (arrayToSearchThrough[i + j] != patternToFind[j])
                    {
                        found = false;
                        break;
                    }
                }
                if (found)
                {
                    return i;
                }
            }
            return -1;
        }

        public static string ByteArrayToString(byte[] ba)
        {
            StringBuilder hex = new StringBuilder(ba.Length * 2);
            foreach (byte b in ba)
                hex.AppendFormat("{0:x2}", b);
            return hex.ToString();
        }


    }
}