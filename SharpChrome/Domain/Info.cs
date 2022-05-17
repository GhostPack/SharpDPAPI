using System;

namespace SharpChrome.Domain
{
    public static class Info
    {
        public static void ShowLogo()
        {
            Console.WriteLine("\r\n  __                 _                     ");
            Console.WriteLine(" (_  |_   _. ._ ._  /  |_  ._ _  ._ _   _      ");
            Console.WriteLine(" __) | | (_| |  |_) \\_ | | | (_) | | | (/_     ");
            Console.WriteLine("                |                              ");
            Console.WriteLine("  v{0}                               \r\n", SharpDPAPI.Version.version);
        }

        public static void ShowUsage()
        {
            string usage = @"
Retrieve a domain controller's DPAPI backup key, optionally specifying a DC and output file:

  SharpChrome backupkey [/nowrap] [/server:SERVER.domain] [/file:key.pvk]


Global arguments for the 'cookies', 'logins', and 'statekeys' commands:

    Decryption:
        /unprotect          -   force use of CryptUnprotectData() (default for unprivileged execution)
        /password:X         -   first decrypt the current user's masterkeys using a plaintext password. Works with any function, as well as remotely.
        GUID1:SHA1 ...      -   use a one or more GUID:SHA1 masterkeys for decryption
        /mkfile:FILE        -   use a file of one or more GUID:SHA1 masterkeys for decryption
        /pvk:BASE64...      -   use a base64'ed DPAPI domain private key file to first decrypt reachable user masterkeys
        /pvk:key.pvk        -   use a DPAPI domain private key file to first decrypt reachable user masterkeys
        /statekey:X         -   a decrypted AES state key (from the 'statekey' command)
    
    Targeting:
        /target:FILE        -   triage a specific 'Cookies', 'Login Data', or 'Local State' file location
        /target:C:\Users\X\ -   triage a specific user folder for any specified command
        /server:SERVER      -   triage a remote server, assuming admin access (note: must use with /pvk:KEY)
        /browser:X          -   triage 'chrome' (the default) or (chromium-based) 'edge'/'brave'
    
    Output:
        /format:X           -   either 'csv' (default) or 'table' display
        /showall            -   show Login Data entries with null passwords and expired Cookies instead of filtering (default)
        /consoleoutfile:X   -   output all console output to a file on disk
        /quiet              -   don't output headers/etc. (for .csv/.json file output)


'cookies' command specific arguments:
    
        /cookie:""REGEX""     -   only return cookies where the cookie name matches the supplied regex
        /url:""REGEX""        -   only return cookies where the cookie URL matches the supplied regex
        /format:json        -   output cookie values in an Cookie-Editor JSON import format. Best when used with a regex!
        /setneverexpire     -   set expirations for cookies output to now + 100 years (for json output)

";
            Console.WriteLine(usage);
        }
    }
}
