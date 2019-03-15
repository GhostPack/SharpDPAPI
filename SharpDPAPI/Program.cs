using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace SharpDPAPI
{
    class Program
    {
        static void Logo()
        {
            Console.WriteLine("\r\n  __                 _   _       _ ___ ");
            Console.WriteLine(" (_  |_   _. ._ ._  | \\ |_) /\\  |_) |  ");
            Console.WriteLine(" __) | | (_| |  |_) |_/ |  /--\\ |  _|_ ");
            Console.WriteLine("                |                      ");
            Console.WriteLine("  v1.1                                 \r\n");
        }

        static void Usage()
        {
            Console.WriteLine("\r\nTriage all reachable masterkey files, use a domain backup key to decrypt all that are found");
            Console.WriteLine("\r\n  SharpDPAPI masterkeys </pvk:BASE64... | /pvk:key.pvk>\r\n");

            Console.WriteLine("\r\nTriage all reachable Credential files, Vaults, or both using a domain DPAPI backup key to decrypt masterkeys:");
            Console.WriteLine("\r\n  SharpDPAPI <credentials|vaults|triage> </pvk:BASE64... | /pvk:key.pvk>\r\n");

            Console.WriteLine("\r\nTriage all reachable Credential files or Vaults, or both optionally using the GUID masterkey mapping to decrypt any matches:");
            Console.WriteLine("\r\n  SharpDPAPI <credentials|vaults|triage> [GUID1:SHA1 GUID2:SHA1 ...]\r\n");

            Console.WriteLine("\r\nTriage a specific Credential file or folder, using GUID lookups or a domain backup key for decryption:");
            Console.WriteLine("\r\n  SharpDPAPI credentials /target:C:\\FOLDER\\ [GUID1:SHA1 GUID2:SHA1 ... | /pvk:BASE64... | /pvk:key.pvk]");
            Console.WriteLine("  SharpDPAPI credentials /target:C:\\FOLDER\\FILE [GUID1:SHA1 GUID2:SHA1 ... | /pvk:BASE64... | /pvk:key.pvk]\r\n");

            Console.WriteLine("\r\nTriage a specific Vault folder, using GUID lookups or a domain backup key for decryption:");
            Console.WriteLine("\r\n  SharpDPAPI vaults /target:C:\\FOLDER\\ [GUID1:SHA1 GUID2:SHA1 ... | /pvk:BASE64... | /pvk:key.pvk]\r\n");

            Console.WriteLine("\r\nRetrieve a domain controller's DPAPI backup key, optionally specifying a DC and output file:");
            Console.WriteLine("\r\n  SharpDPAPI backupkey [/server:primary.testlab.local] [/file:key.pvk]\r\n");
        }

        static void Main(string[] args)
        {
			try {
				Logo();

				if (args.Length < 1)
				{
					Usage();
					return;
				}

				var arguments = new Dictionary<string, string>();
				foreach (string argument in args)
				{
					int idx = argument.IndexOf(':');
					if (idx > 0)
					{
						string key = argument.Substring(0, idx);
						string value = argument.Substring(idx + 1);

						if (!key.StartsWith("/"))
						{
							// meaning the guid:masterkey mappings. we want to ensure standard {GUID}:SHA1 formatting
							if (!key.StartsWith("{"))
							{
								key = String.Format("{{{0}}}", key);
							}
						}

						arguments[key] = value;
					}
					else
					{
						arguments[argument] = "";
					}
				}

				if (arguments.ContainsKey("backupkey"))
				{
					Console.WriteLine("\r\n[*] Action: Retrieve domain DPAPI backup key\r\n");
					string server = "";
					string outFile = "";

					if (arguments.ContainsKey("/server"))
					{
						server = arguments["/server"];
						Console.WriteLine("\r\n[*] Using server                     : {0}", server);
					}
					else
					{
						server = Interop.GetDCName();
						if (String.IsNullOrEmpty(server))
						{
							return;
						}
						Console.WriteLine("\r\n[*] Using current domain controller  : {0}", server);
					}

					if (arguments.ContainsKey("/file"))
					{
						outFile = arguments["/file"];
					}

					Backup.GetBackupKey(server, outFile);
				}

				if (arguments.ContainsKey("masterkeys"))
				{
					Console.WriteLine("\r\n[*] Action: Triage Masterkey Files\r\n");
					byte[] backupKeyBytes;
					
					if (arguments.ContainsKey("/pvk"))
					{
						string pvk64 = arguments["/pvk"];
						if (File.Exists(pvk64))
						{
							backupKeyBytes = File.ReadAllBytes(pvk64);
						}
						else
						{
							backupKeyBytes = Convert.FromBase64String(pvk64);
						}
					}
					else
					{
						Console.WriteLine("[X] A /pvk:BASE64 domain DPAPI backup key must be supplied!");
						return;
					}

					Dictionary<string, string> mappings = Triage.TriageMasterKeys(backupKeyBytes, true);

					Console.WriteLine("\r\n[*] Master key cache:\r\n");
					foreach (KeyValuePair<string, string> kvp in mappings)
					{
						Console.WriteLine("{0}:{1}", kvp.Key, kvp.Value);
					}
					return;
				}

				else if (arguments.ContainsKey("credentials"))
				{
					Console.WriteLine("\r\n[*] Action: DPAPI Credential Triage\r\n");
					arguments.Remove("credentials");

					if (arguments.ContainsKey("/target"))
					{
						string target = arguments["/target"];
						arguments.Remove("/target");

						if (arguments.ContainsKey("/pvk"))
						{
							// using a domain backup key to decrypt everything
							string pvk64 = arguments["/pvk"];
							byte[] backupKeyBytes;

							if (File.Exists(pvk64))
							{
								backupKeyBytes = File.ReadAllBytes(pvk64);
							}
							else
							{
								backupKeyBytes = Convert.FromBase64String(pvk64);
							}

							// build a {GUID}:SHA1 masterkey mappings
							Dictionary<string, string> mappings = Triage.TriageMasterKeys(backupKeyBytes, false);

							Console.WriteLine("[*] Using a domain DPAPI backup key to triage masterkeys for decryption key mappings!\r\n");
							arguments = mappings;
						}

						if (File.Exists(target))
						{
							Console.WriteLine("[*] Target Credential File: {0}\r\n", target);
							Triage.TriageCredFile(target, arguments);
						}
						else if (Directory.Exists(target))
						{
							Console.WriteLine("[*] Target Credential Folder: {0}\r\n", target);
							Triage.TriageCredFolder(target, arguments);
						}
						else
						{
							Console.WriteLine("\r\n[X] '{0}' is not a valid file or directory.", target);
						}
					}

					else if (arguments.ContainsKey("/pvk"))
					{
						// using a domain backup key to decrypt everything
						string pvk64 = arguments["/pvk"];

						byte[] backupKeyBytes;

						if (File.Exists(pvk64))
						{
							backupKeyBytes = File.ReadAllBytes(pvk64);
						}
						else
						{
							backupKeyBytes = Convert.FromBase64String(pvk64);
						}

						// build a {GUID}:SHA1 masterkey mappings
						Dictionary<string, string> mappings = Triage.TriageMasterKeys(backupKeyBytes, false);
						
						Console.WriteLine("[*] Using a domain DPAPI backup key to triage masterkeys for decryption key mappings!\r\n");

						Triage.TriageCreds(mappings);
						return;
					}
					else
					{
						Triage.TriageCreds(arguments);
					}
				}

				else if (arguments.ContainsKey("vaults"))
				{
					Console.WriteLine("\r\n[*] Action: DPAPI Vault Triage\r\n");
					arguments.Remove("vaults");

					if (arguments.ContainsKey("/target"))
					{
						string target = arguments["/target"];
						arguments.Remove("/target");

						if (arguments.ContainsKey("/pvk"))
						{
							// using a domain backup key to decrypt everything
							string pvk64 = arguments["/pvk"];
							byte[] backupKeyBytes;

							if (File.Exists(pvk64))
							{
								backupKeyBytes = File.ReadAllBytes(pvk64);
							}
							else
							{
								backupKeyBytes = Convert.FromBase64String(pvk64);
							}

							// build a {GUID}:SHA1 masterkey mappings
							Dictionary<string, string> mappings = Triage.TriageMasterKeys(backupKeyBytes, false);

							Console.WriteLine("[*] Using a domain DPAPI backup key to triage masterkeys for decryption key mappings!\r\n");
							arguments = mappings;
						}

						if (Directory.Exists(target))
						{
							Console.WriteLine("[*] Target Vault Folder: {0}\r\n", target);
							Triage.TriageVaultFolder(target, arguments);
						}
						else
						{
							Console.WriteLine("\r\n[X] '{0}' is not a valid Vault directory.", target);
						}
					}
					else if (arguments.ContainsKey("/pvk"))
					{
						// using a domain backup key to decrypt everything
						string pvk64 = arguments["/pvk"];

						byte[] backupKeyBytes;

						if (File.Exists(pvk64))
						{
							backupKeyBytes = File.ReadAllBytes(pvk64);
						}
						else
						{
							backupKeyBytes = Convert.FromBase64String(pvk64);
						}

						// build a {GUID}:SHA1 masterkey mappings
						Dictionary<string, string> mappings = Triage.TriageMasterKeys(backupKeyBytes, false);

						Console.WriteLine("[*] Using a domain DPAPI backup key to triage masterkeys for decryption key mappings!\r\n");

						Triage.TriageVaults(mappings);
						return;
					}
					else
					{
						Triage.TriageVaults(arguments);
					}
				}

				else if (arguments.ContainsKey("triage"))
				{
					Console.WriteLine("\r\n[*] Action: DPAPI Credential and Vault Triage\r\n");
					arguments.Remove("triage");

					if (arguments.ContainsKey("/pvk"))
					{
						// using a domain backup key to decrypt everything
						string pvk64 = arguments["/pvk"];
						byte[] backupKeyBytes = Convert.FromBase64String(pvk64);
						Dictionary<string, string> mappings = Triage.TriageMasterKeys(backupKeyBytes, false);

						Console.WriteLine("[*] Using a domain DPAPI backup key to triage masterkeys for decryption key mappings!\r\n");

						Triage.TriageCreds(mappings);
						Triage.TriageVaults(mappings);
						return;
					}

					else
					{
						Triage.TriageCreds(arguments);
						Triage.TriageVaults(arguments);
					}
				}

				else
				{
					Usage();
				}
			} catch(Exception e) {
				Console.WriteLine("Unhandled error: " + e);
			}
		}
    }
}
