using System;

namespace SharpDPAPI.Domain
{
    public static class Info
    {
        public static void Logo()
        {
            Console.WriteLine("\r\n  __                 _   _       _ ___ ");
            Console.WriteLine(" (_  |_   _. ._ ._  | \\ |_) /\\  |_) |  ");
            Console.WriteLine(" __) | | (_| |  |_) |_/ |  /--\\ |  _|_ ");
            Console.WriteLine("                |                      ");
            Console.WriteLine("  v{0}                               \r\n", SharpDPAPI.Version.version);
        }

        public static void ShowUsage()
        {
            string usage = @"

Retrieve a domain controller's DPAPI backup key, optionally specifying a DC and output file:

  SharpDPAPI backupkey [/server:SERVER.domain] [/file:key.pvk]


Machine/SYSTEM Triage:

    machinemasterkeys       -   triage all reachable machine masterkey files (elevates to SYSTEM to retrieve the DPAPI_SYSTEM LSA secret)
    machinecredentials      -   use 'machinemasterkeys' and then triage machine Credential files
    machinevaults           -   use 'machinemasterkeys' and then triage machine Vaults
    machinecerts           -   use 'machinemasterkeys' and then triage machine certificate stores
    machinetriage           -   run the 'machinecredentials' and 'machinevaults' commands


User Triage:

    Triage all reachable user masterkey files, use a domain backup key to decrypt all that are found:

      SharpDPAPI masterkeys </pvk:BASE64... | /pvk:key.pvk>    


    Arguments for the certificates|credentials|vaults|rdg|triage|blob|ps commands:

        Decryption:
            /unprotect          -   force use of CryptUnprotectData() for 'ps', 'rdg', or 'blob' commands
            /password:X         -   first decrypt the current user's masterkeys using a plaintext password. Works with any function, as well as remotely.
            GUID1:SHA1 ...      -   use a one or more GUID:SHA1 masterkeys for decryption
            /mkfile:FILE        -   use a file of one or more GUID:SHA1 masterkeys for decryption
            /pvk:BASE64...      -   use a base64'ed DPAPI domain private key file to first decrypt reachable user masterkeys
            /pvk:key.pvk        -   use a DPAPI domain private key file to first decrypt reachable user masterkeys

        Targeting:
            /target:FILE/folder -   triage a specific 'Credentials','.rdg|RDCMan.settings', 'blob', or 'ps' file location, or 'Vault' folder
            /server:SERVER      -   triage a remote server, assuming admin access
                                    Note: must use with /pvk:KEY
                                    Note: not applicable to 'blob' or 'ps' commands


Note: in most cases, just use *triage* if you're targeting user DPAPI secrets and *machinetriage* if you're going after SYSTEM DPAPI secrets.
      These functions wrap all the other applicable functions that can be automatically run.

";
            Console.WriteLine(usage);
        }
    }
}
