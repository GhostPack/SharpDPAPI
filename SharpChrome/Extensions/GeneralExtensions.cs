using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;
using Community.CsharpSqlite;
using SharpDPAPI;
using static Community.CsharpSqlite.Sqlite3;
using DateTime = System.DateTime;

namespace SharpChrome.Extensions
{
    public static class GeneralExtensions
    {
        /// <summary>
        /// Reads the current <see cref="Stream"/> as a <see cref="string"/>, optionally using a given <paramref name="encoding"/>.
        /// <para>Will also reset the Stream's internal position to 0 so it can be re-read again.</para>
        /// </summary>
        /// <param name="stream"></param>
        /// <param name="encoding"></param>
        /// <returns></returns>
        public static async Task<string> ReadAsStringAsync(this Stream stream, Encoding encoding = null)
        {
            stream.Position = 0;
            var streamReader = encoding == null
                ? new StreamReader(stream, detectEncodingFromByteOrderMarks: true)
                : new StreamReader(stream, encoding);

            var @string = await streamReader.ReadToEndAsync();
            stream.Position = 0; // reset position
            return @string;
        }

        /// <summary>
        /// Reads the current <see cref="Stream"/> as a <see cref="string"/>, optionally using a given <paramref name="encoding"/>.
        /// <para>Will also reset the Stream's internal position to 0 so it can be re-read again.</para>
        /// </summary>
        /// <param name="stream"></param>
        /// <param name="encoding"></param>
        /// <returns></returns>
        public static string ReadAsString(this Stream stream, Encoding encoding = null)
        {
            stream.Position = 0;
            var streamReader = encoding == null
                ? new StreamReader(stream, detectEncodingFromByteOrderMarks: true)
                : new StreamReader(stream, encoding);

            var @string = streamReader.ReadToEnd();
            stream.Position = 0; // reset position
            return @string;
        }

        public static List<logins> DecryptPasswords(this IEnumerable<logins> logins, byte[] aesStateKey)
        {
            if (aesStateKey == null || aesStateKey.Length == default) throw new ArgumentNullException(nameof(aesStateKey));

            BCrypt.SafeAlgorithmHandle hAlg = null;
            BCrypt.SafeKeyHandle hKey = null;

            var keyDecryptResult = Chrome.DPAPIChromeAlgKeyFromRaw(aesStateKey, out hAlg, out hKey);
            var loginsList = logins.ToList();

            foreach (var login in loginsList) {
                byte[] passwordBytes = login.password_value;
                byte[] decBytes = null;
                string password = null;

                if (HasV10Header(passwordBytes)) {
                    // using the new DPAPI decryption method
                    decBytes = Chrome.DecryptAESChromeBlob(passwordBytes, hAlg, hKey);

                    if (decBytes == null) {
                        throw new Exception($"Unable to decrypt {nameof(login.password_value)} ({login.username_value} :: {login.origin_url})");
                    }
                }
                else {
                    // using the old method
                    Dictionary<string, string> masterKeys = new Dictionary<string, string>();
                    decBytes = SharpDPAPI.Dpapi.DescribeDPAPIBlob(blobBytes: passwordBytes, MasterKeys: masterKeys, blobType: "chrome");
                }

                password = Encoding.ASCII.GetString(decBytes);

                login.setDecrypted_password_value(password);
            }


            return loginsList;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static bool HasV10Header(this byte[] data) => Chrome.HasV10Header(data);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static DateTime FromChromeTimeToDateTime(this double bigIntegerValue) => Helpers.ConvertToDateTime(bigIntegerValue);
        
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static double FromDateTimeToChromeTime(this DateTime dateTimeValue) => Helpers.ConvertToChromeTime(dateTimeValue);
    }
}