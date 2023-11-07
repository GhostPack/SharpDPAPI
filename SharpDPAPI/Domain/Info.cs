using System;

namespace SharpDPAPI.Domain
{
    public static class Info
    {
        public static void ShowLogo()
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

  SharpDPAPI backupkey [/nowrap] [/server:SERVER.domain] [/file:key.pvk]


The *search* comand will search for potential DPAPI blobs in the registry, files, folders, and base64 blobs:
    
    search /type:registry [/path:HKLM\path\to\key] [/showErrors]
    search /type:folder /path:C:\path\to\folder [/maxBytes:<numOfBytes>] [/showErrors]
    search /type:file /path:C:\path\to\file [/maxBytes:<numOfBytes>]
    search /type:base64 [/base:<base64 string>]


Machine/SYSTEM Triage:

    machinemasterkeys       -   triage all reachable machine masterkey files (elevates to SYSTEM to retrieve the DPAPI_SYSTEM LSA secret)
    machinecredentials      -   use 'machinemasterkeys' and then triage machine Credential files
    machinevaults           -   use 'machinemasterkeys' and then triage machine Vaults
    machinetriage           -   run the 'machinecredentials' and 'machinevaults' commands


User Triage:

    Arguments for the 'masterkeys' command:

        /target:FILE/folder     -   triage a specific masterkey, or a folder full of masterkeys (otherwise triage local masterkeys)
        /pvk:BASE64...          -   use a base64'ed DPAPI domain private key file to first decrypt reachable user masterkeys
        /pvk:key.pvk            -   use a DPAPI domain private key file to first decrypt reachable user masterkeys
        /password:X             -   first decrypt the current user's masterkeys using a plaintext password (works remotely)
        /server:SERVER          -   triage a remote server, assuming admin access
        /rpc                    -   attempt to decrypt user masterkeys by asking domaine controller to do so


    Arguments for the credentials|vaults|rdg|keepass|triage|blob|ps commands:

        Decryption:
            /unprotect          -   force use of CryptUnprotectData() for 'ps', 'rdg', or 'blob' commands
            /password:X         -   first decrypt the current user's masterkeys using a plaintext password. Works with any function, as well as remotely.
            GUID1:SHA1 ...      -   use a one or more GUID:SHA1 masterkeys for decryption
            /mkfile:FILE        -   use a file of one or more GUID:SHA1 masterkeys for decryption
            /pvk:BASE64...      -   use a base64'ed DPAPI domain private key file to first decrypt reachable user masterkeys
            /pvk:key.pvk        -   use a DPAPI domain private key file to first decrypt reachable user masterkeys
            /rpc                    -   attempt to decrypt user masterkeys by asking domaine controller to do so

        Targeting:
            /target:FILE/folder -   triage a specific 'Credentials','.rdg|RDCMan.settings', 'blob', or 'ps' file location, or 'Vault' folder
            /server:SERVER      -   triage a remote server, assuming admin access
                                    Note: must use with /pvk:KEY or /password:X
                                    Note: not applicable to 'blob' or 'ps' commands


Certificate Triage:

    Arguments for the 'certificates' command:
        /showall                                        -   show all decrypted private key files, not just ones that are linked to installed certs (the default)
        /machine                                        -   use the local machine store for certificate triage
        /mkfile | /target                               -   for /machine triage
        /unprotect                                      -   force use of CryptUnprotectData() for user triage
        /pvk | /mkfile | /password | /server | /target  -   for user triage
    

Note: in most cases, just use *triage* if you're targeting user DPAPI secrets and *machinetriage* if you're going after SYSTEM DPAPI secrets.
      These functions wrap all the other applicable functions that can be automatically run.

";
            Console.WriteLine(usage);
        }
    }
}
