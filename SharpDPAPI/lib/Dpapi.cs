using PBKDF2;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Data.SqlTypes;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;

namespace SharpDPAPI
{
    public class Dpapi
    {
        public static Tuple<string, byte[]> DescribeDPAPICertPrivateKey(string fileName, byte[] dpapiblob, Dictionary<string, string> MasterKeys, byte[] entropy = null, bool unprotect = false)
        {
            // decrypts the private key part of a CAPI/CNG blog

            byte[] decrypted = new byte[0];
            string message = "";
            var offset = 0;

            var dpapiversion = BitConverter.ToUInt32(dpapiblob, offset);

            offset += 4;
            var provider = new byte[16];
            Array.Copy(dpapiblob, offset, provider, 0, 16);
            var guidProvider = new Guid(provider);
            var strGuidProvider = $"{{{guidProvider}}}";

            offset += provider.Length;
            var blobStart = offset;
            var mkversion = BitConverter.ToUInt32(dpapiblob, offset);

            offset += 4;
            var mkguid = new byte[16];
            Array.Copy(dpapiblob, offset, mkguid, 0, 16);
            var mkguidProvider = new Guid(mkguid);
            var strmkguidProvider = $"{{{mkguidProvider}}}";

            offset += 16;
            var mkflags = BitConverter.ToUInt32(dpapiblob, offset);

            offset += 4;
            var descrlen = BitConverter.ToInt32(dpapiblob, offset);

            offset += 4;
            var description = Encoding.Unicode.GetString(dpapiblob, offset, descrlen).Replace("\0", string.Empty);

            offset += descrlen;
            var algCrypt = BitConverter.ToInt32(dpapiblob, offset);

            offset += 4;
            var algCryptLen = BitConverter.ToInt32(dpapiblob, offset);
            
            offset += 4;
            var saltBytes = new byte[BitConverter.ToUInt32(dpapiblob, offset)];
            Array.Copy(dpapiblob, offset + 4, saltBytes, 0, BitConverter.ToUInt32(dpapiblob, offset));

            offset += saltBytes.Length + 8; //skipped strong structure
            var algHash = BitConverter.ToInt32(dpapiblob, offset);

            offset += 4;
            var hashlen = BitConverter.ToInt32(dpapiblob, offset);

            offset += 4;
            var hmac = new byte[BitConverter.ToUInt32(dpapiblob, offset)];
            Array.Copy(dpapiblob, offset + 4, hmac, 0, BitConverter.ToUInt32(dpapiblob, offset));

            offset += hmac.Length + 4;
            var cipherText = new byte[BitConverter.ToUInt32(dpapiblob, offset)];
            Array.Copy(dpapiblob, offset + 4, cipherText, 0, BitConverter.ToUInt32(dpapiblob, offset));

            offset += cipherText.Length + 4;

            var selfblobBytes = new byte[offset - blobStart];
            Array.Copy(dpapiblob, blobStart, selfblobBytes, 0, offset - blobStart);

            var signBytes = new byte[BitConverter.ToUInt32(dpapiblob, offset)];
            Array.Copy(dpapiblob, offset + 4, signBytes, 0, BitConverter.ToUInt32(dpapiblob, offset));

            offset += signBytes.Length + 4;

            if (unprotect)
            {
                // use CryptUnprotectData()
                try
                {
                    var decBytes = ProtectedData.Unprotect(dpapiblob, entropy, DataProtectionScope.CurrentUser);
                    if (decBytes.Length > 0)
                    {
                        message += $"\n    Provider GUID    : {strGuidProvider}\n";
                        message += $"    Master Key GUID  : {strmkguidProvider}\n";
                        message += $"    Description      : {description}\n";
                        message += $"    algCrypt         : {(Interop.CryptAlg)algCrypt} (keyLen {algCryptLen})\n";
                        message += $"    algHash          : {(Interop.CryptAlg)algHash} ({algHash})\n";
                        message += $"    Salt             : {Helpers.ByteArrayToString(saltBytes)}\n";
                        message += $"    HMAC             : {Helpers.ByteArrayToString(hmac)}\n";
                    }

                    return new Tuple<string, byte[]>(message, decBytes);
                }
                catch
                {
                    Console.WriteLine($"    [!] {fileName} masterkey needed: {strmkguidProvider}");
                }
            }

            switch (algHash)
            {
                case 32782:
                    try
                    {
                        var keyBytes = Helpers.StringToByteArray(MasterKeys[strmkguidProvider]);
                        var derivedKeyBytes = Crypto.DeriveKey(keyBytes, saltBytes, algHash, entropy);
                        
                        var finalKeyBytes = new byte[algCryptLen / 8];
                        Array.Copy(derivedKeyBytes, finalKeyBytes, algCryptLen / 8);
                         
                        if (entropy != null)
                        {
                            // for CNG, we need a different padding mode
                            decrypted = Crypto.DecryptBlob(cipherText, finalKeyBytes, algCrypt, PaddingMode.PKCS7);
                        }
                        else {
                            decrypted = Crypto.DecryptBlob(cipherText, finalKeyBytes, algCrypt);
                        }
                    }
                    catch (Exception)
                    {
                        Console.WriteLine($"    [!] {fileName} masterkey needed: {strmkguidProvider}");
                    }

                    break;

                // 32772 == CALG_SHA1
                case 32772:
                    try
                    {
                        algCryptLen = 192; //3DES rounding

                        var keyBytes = Helpers.StringToByteArray(MasterKeys[strmkguidProvider]);

                        // derive the session key
                        var derivedKeyBytes = Crypto.DeriveKey(keyBytes, saltBytes, algHash, entropy);

                        var finalKeyBytes = new byte[algCryptLen / 8];
                        Array.Copy(derivedKeyBytes, finalKeyBytes, algCryptLen / 8);

                        //Console.WriteLine($"finalKeyBytes: {BitConverter.ToString(finalKeyBytes).Replace("-", "")}");

                        // decrypt the blob with the session key
                        try
                        {
                            decrypted = Crypto.DecryptBlob(cipherText, finalKeyBytes, algCrypt);
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine("    [X] Error decrypting blob: {0}", ex);
                        }
                    }
                    catch (Exception)
                    {
                        Console.WriteLine($"    [!] {fileName} masterkey needed: {strmkguidProvider}");
                    }

                    break;

                default:
                    Console.WriteLine("    [X] Hash algorithm currently not supported: {0}", algHash);
                    break;
            }

            if(decrypted.Length > 0)
            {
                message += $"\n    Provider GUID    : {strGuidProvider}\n";
                message += $"    Master Key GUID  : {strmkguidProvider}\n";
                message += $"    Description      : {description}\n";
                message += $"    algCrypt         : {(Interop.CryptAlg)algCrypt} (keyLen {algCryptLen})\n";
                message += $"    algHash          : {(Interop.CryptAlg)algHash} ({algHash})\n";
                message += $"    Salt             : {Helpers.ByteArrayToString(saltBytes)}\n";
                message += $"    HMAC             : {Helpers.ByteArrayToString(hmac)}\n";
            }

            return new Tuple<string, byte[]>(message, decrypted);
        }


        public static byte[] ConvertRsaBlobToRsaFullBlob(byte[] rsaKeyBytes, bool debug = false)
        {
            // Uses NCrypt* APIs to convert a BCRYPT_RSAPRIVATE_BLOB (which only contains modulus, E, P, and Q
            //  to a BCRYPT_RSAFULLPRIVATE_BLOB (which contains the other calculated exponents/etc.)

            // https://stackoverflow.com/a/38679324
            //  "While the Windows CAPI (used by RSACryptoServiceProvider) will roundtrip any value of D you import,
            //   it doesn't actually use it. Windows CNG (used by RSACng) requires that D be provided on import of
            //   a private key, then promptly throws it away, recomputing it on export (or import, I suppose)."

            IntPtr hProvider = IntPtr.Zero;
            uint success = Interop.NCryptOpenStorageProvider(out hProvider, "Microsoft Software Key Storage Provider", 0);
            if ((success != 0) && debug)
            {
                Console.WriteLine($"[!] NCryptOpenStorageProvider error: {success}");
            }

            IntPtr hKey = IntPtr.Zero;
            // NCRYPT_DO_NOT_FINALIZE_FLAG -> 0x00000400
            success = Interop.NCryptImportKey(hProvider, IntPtr.Zero, "PRIVATEBLOB", IntPtr.Zero, out hKey, rsaKeyBytes, rsaKeyBytes.Length, 0x00000400);
            if ((success != 0) && debug)
            {
                Console.WriteLine($"[!] NCryptImportKey error: {success}");
            }

            var exportPolicyBytes = BitConverter.GetBytes((int)(CngExportPolicies.AllowExport | CngExportPolicies.AllowPlaintextExport));
            success = Interop.NCryptSetProperty(hKey, "Export Policy", exportPolicyBytes, exportPolicyBytes.Length, 0);
            if ((success != 0) && debug)
            {
                Console.WriteLine($"[!] NCryptSetProperty error: {success}");
            }

            success = Interop.NCryptFinalizeKey(hKey, 0);
            if ((success != 0) && debug)
            {
                Console.WriteLine($"[!] NCryptFinalizeKey error: {success}");
            }

            int pcbResult = 0;
            //success = Interop.NCryptExportKey(hKey, IntPtr.Zero, "PKCS8_PRIVATEKEY", IntPtr.Zero, null, 0, out pcbResult, 0);
            success = Interop.NCryptExportKey(hKey, IntPtr.Zero, "RSAFULLPRIVATEBLOB", IntPtr.Zero, null, 0, out pcbResult, 0);
            if ((success != 0) && debug)
            {
                Console.WriteLine($"[!] NCryptExportKey error: {success}");
            }

            byte[] exported = new byte[pcbResult];
            //success = Interop.NCryptExportKey(hKey, IntPtr.Zero, "PKCS8_PRIVATEKEY", IntPtr.Zero, exported, pcbResult, out pcbResult, 0);
            success = Interop.NCryptExportKey(hKey, IntPtr.Zero, "RSAFULLPRIVATEBLOB", IntPtr.Zero, exported, pcbResult, out pcbResult, 0);
            if ((success != 0) && debug)
            {
                Console.WriteLine($"[!] NCryptExportKey error: {success}");
            }

            success = Interop.NCryptFreeObject(hKey);
            if ((success != 0) && debug)
            {
                Console.WriteLine($"[!] NCryptFreeObject(hKey) error: {success}");
            }

            success = Interop.NCryptFreeObject(hProvider);
            if ((success != 0) && debug)
            {
                Console.WriteLine($"[!] NCryptFreeObject(hProvider) error: {success}");
            }

            return exported;
        }


        public static Tuple<string, byte[]> DescribeCngCertBlob(string fileName, byte[] blobBytes, Dictionary<string, string> MasterKeys, bool unprotect = false)
        {
            // Parses a CNG certificate private key blob, decrypting if possible.

            // based on @gentilkiwi's structure - https://github.com/gentilkiwi/mimikatz/blob/fe4e98405589e96ed6de5e05ce3c872f8108c0a0/modules/kull_m_key.h#L51-L68

            var offset = 0;
            var version = BitConverter.ToUInt32(blobBytes, offset);

            offset += 8; //consuming a null byte (unk0)
            var descrLen = BitConverter.ToUInt32(blobBytes, offset);

            offset += 4;
            var type = BitConverter.ToUInt32(blobBytes, offset);

            offset += 4;
            var dwPublicPropertiesLen = BitConverter.ToUInt32(blobBytes, offset);

            offset += 4;
            var dwPrivatePropertiesLen = BitConverter.ToUInt32(blobBytes, offset);

            offset += 4;
            var dwPrivateKeyLen = BitConverter.ToUInt32(blobBytes, offset);

            offset += 16; // BYTE	unkArray[16];

            offset += 4;
            var description = new byte[descrLen];

            Array.Copy(blobBytes, offset, description, 0, descrLen);
            var descriptionString = Encoding.Unicode.GetString(description, 0, description.Length).Replace("\0", string.Empty); ;

            offset += description.Length;
            offset += (int)dwPublicPropertiesLen;
            offset += (int)dwPrivatePropertiesLen;

            var dpapiblob = new byte[dwPrivateKeyLen];
            Array.Copy(blobBytes, offset, dpapiblob, 0, dwPrivateKeyLen);

            // entropy needed - https://github.com/gentilkiwi/mimikatz/blob/fa42ed93aa4d5aa73825295e2ab757ac96005581/modules/kull_m_key.h#L13
            Tuple<string, byte[]> result = DescribeDPAPICertPrivateKey(fileName, dpapiblob, MasterKeys, Helpers.Combine(Encoding.UTF8.GetBytes("xT5rZW5qVVbrvpuA"), new byte[1]),unprotect);

            string message = result.First;
            if (result.Second.Length > 0)
            {
                message += $"    Unique Name      : {descriptionString}\n";
            }

            return new Tuple<string, byte[]>(message, ConvertRsaBlobToRsaFullBlob(result.Second));
        }


        public static Tuple<string, byte[]> DescribeCapiCertBlob(string fileName, byte[] blobBytes, Dictionary<string, string> MasterKeys, bool unprotect = false)
        {
            // Parses a CAPI certificate private key blob, decrypting if possible.

            // ~Based heavily on dpapick from @jmichel_p https://bitbucket.org/jmichel/dpapick/~
            // 2021-01-04: update to @gentilkiwi's structure - https://github.com/gentilkiwi/mimikatz/blob/fe4e98405589e96ed6de5e05ce3c872f8108c0a0/modules/kull_m_key.h#L18-L38

            var offset = 0;
            var version = BitConverter.ToUInt32(blobBytes, offset);

            offset += 8; //consuming a null byte (unk0)
            var descrLen = BitConverter.ToUInt32(blobBytes, offset);

            offset += 4;
            var siPublicKeyLen = BitConverter.ToUInt32(blobBytes, offset);

            offset += 4;
            var siPrivateKeyLen = BitConverter.ToUInt32(blobBytes, offset);

            offset += 4;
            var exPublicKeyLen = BitConverter.ToUInt32(blobBytes, offset);

            offset += 4;
            var exPrivateKeyLen = BitConverter.ToUInt32(blobBytes, offset);
                
            offset += 4;
            var hashLen = BitConverter.ToUInt32(blobBytes, offset);

            offset += 4;
            var siExportFlagLen = BitConverter.ToUInt32(blobBytes, offset);

            offset += 4;
            var exExportFlagLen = BitConverter.ToUInt32(blobBytes, offset);

            offset += 4;
            var descriptionGUID = new byte[descrLen];

            Array.Copy(blobBytes, offset, descriptionGUID, 0, descrLen);
            var descriptionString = Encoding.UTF8.GetString(descriptionGUID, 0, descriptionGUID.Length).Replace("\0", string.Empty); ;

            offset += descriptionGUID.Length;
            var crc = new byte[hashLen];
            Array.Copy(blobBytes, offset, crc, 0, hashLen);
            var crcStr = Helpers.ByteArrayToString(crc);
            offset += (int)hashLen;

            if (blobBytes.Length > offset)
            {
                var magicStr = Encoding.UTF8.GetString(blobBytes, offset, 4);

                offset += 4;
                var len1 = BitConverter.ToUInt32(blobBytes, offset);

                offset += 4;
                var bitlength = BitConverter.ToUInt32(blobBytes, offset);
                //Console.WriteLine("    Bitlength: {0}", bitlength); //0x400

                offset += 4;
                var unk = BitConverter.ToUInt32(blobBytes, offset);
                
                offset += 4;
                var pubexp = BitConverter.ToUInt32(blobBytes, offset);
                
                offset += 4;
                var data = new byte[bitlength / 8];
                Array.Copy(blobBytes, offset, data, 0, bitlength / 8); //TODO

                offset += (int)bitlength / 8 + 8;

                if ((siPrivateKeyLen == 0) && (exPrivateKeyLen == 0))
                {
                    // Console.WriteLine("\r\n    [*] No decryptable private keys available");
                }
                else
                {
                    uint len = 0;

                    if (exPublicKeyLen != 0)
                    {
                        len = exPrivateKeyLen;
                    }
                    else
                    {
                        len = siPrivateKeyLen;
                    }

                    var dpapiblob = new byte[len];
                    Array.Copy(blobBytes, offset, dpapiblob, 0, len);

                    Tuple<string, byte[]> result = DescribeDPAPICertPrivateKey(fileName, dpapiblob, MasterKeys, null, unprotect);
                    string message = result.First;
                    if(result.Second.Length > 0)
                    {
                        message += $"    Unique Name      : {descriptionString}\n";
                    }

                    return new Tuple<string, byte[]>(message, result.Second);
                }
            }

            return new Tuple<string, byte[]>("", null);
        }


        public static ExportedCertificate DescribeCertificate(string fileName, byte[] certificateBytes, Dictionary<string, string> MasterKeys, bool cng = false, bool alwaysShow = false, bool unprotect = false)
        {
            // takes a raw certificate private key blob and decrypts/displays if possible

            Tuple<string, byte[]> result = new Tuple<string, byte[]>("", null);
            if (cng)
            {
                result = DescribeCngCertBlob(fileName, certificateBytes, MasterKeys, unprotect);
            }
            else
            {
                result = DescribeCapiCertBlob(fileName, certificateBytes, MasterKeys, unprotect);
            }

            string statusMessage = result.First;
            byte[] privKeyBytes = result.Second;
            //Console.WriteLine("decrypted result: {0}", Convert.ToBase64String(result.Second));

            var certificate = new ExportedCertificate();
            
            if ((privKeyBytes != null) && (privKeyBytes.Length > 0))
            {
                Tuple<string, string> decryptedRSATuple = null;

                if (cng)
                {
                    decryptedRSATuple = ParseDecCngCertBlob(privKeyBytes);
                }
                else
                {
                    decryptedRSATuple = ParseDecCapiCertBlob(privKeyBytes);
                }

                var PrivatePKCS1 = decryptedRSATuple.First;
                var PrivateXML = decryptedRSATuple.Second;

                if (alwaysShow)
                {
                    Console.WriteLine("  File               : {0}", fileName);
                    Console.WriteLine(statusMessage);
                    certificate.PrivateKey = PrivatePKCS1;
                }

                X509Certificate2Collection certCollection;
                try
                {
                    foreach (var storeLocation in new Enum[] { StoreLocation.CurrentUser, StoreLocation.LocalMachine })
                    {
                        X509Store store = new X509Store((StoreLocation)storeLocation);
                        store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
                        certCollection = store.Certificates;
                        store.Close();

                        foreach (var cert in certCollection)
                        {
                            var PublicXML = cert.PublicKey.Key.ToXmlString(false).Replace("</RSAKeyValue>", "");

                            //There are cases where systems have a lot of "orphaned" private keys. We are only grabbing private keys that have a matching modulus with a cert in the store
                            //https://forums.iis.net/t/1224708.aspx?C+ProgramData+Microsoft+Crypto+RSA+MachineKeys+is+filling+my+disk+space
                            //https://superuser.com/questions/538257/why-are-there-so-many-files-in-c-programdata-microsoft-crypto-rsa-machinekeys
                            if (PrivateXML.Contains(PublicXML))
                            {
                                // only display all of the status messages if we have a decrypted private key that corresponds to a cert found in a store location
                                if (!alwaysShow)
                                {
                                    Console.WriteLine("  File               : {0}", fileName);
                                    Console.WriteLine(statusMessage);
                                }

                                certificate.Issuer = cert.Issuer;
                                certificate.Subject = cert.Subject;
                                certificate.ValidDate = cert.NotBefore.ToString();
                                certificate.ExpiryDate = cert.NotAfter.ToString();
                                certificate.Thumbprint = cert.Thumbprint;

                                foreach (var ext in cert.Extensions)
                                {
                                    if (ext.Oid.FriendlyName == "Enhanced Key Usage")
                                    {
                                        var extUsages = ((X509EnhancedKeyUsageExtension)ext).EnhancedKeyUsages;

                                        if (extUsages.Count > 0)
                                        {
                                            foreach (var extUsage in extUsages)
                                            {
                                                var eku = new Tuple<string, string>(extUsage.FriendlyName, extUsage.Value);
                                                certificate.EKUs.Add(eku);
                                            }
                                        }
                                    }
                                }

                                string b64cert = Convert.ToBase64String(cert.Export(X509ContentType.Cert));
                                int BufferSize = 64;
                                int Index = 0;
                                var sb = new StringBuilder();
                                sb.AppendLine("-----BEGIN CERTIFICATE-----");
                                for (var i = 0; i < b64cert.Length; i += 64)
                                {
                                    sb.AppendLine(b64cert.Substring(i, Math.Min(64, b64cert.Length - i)));
                                    Index += BufferSize;
                                }
                                sb.AppendLine("-----END CERTIFICATE-----");

                                certificate.PrivateKey = PrivatePKCS1;
                                certificate.PublicCertificate = sb.ToString();

                                //// Commented code for pfx generation due to MS not giving 
                                ////a dispose method < .NET4.6 https://snede.net/the-most-dangerous-constructor-in-net/
                                ////   X509Certificate2 certificate = new X509Certificate2(cert.RawData);
                                ////   certificate.PrivateKey = ;
                                ////       string filename = string.Format("{0}.pfx", cert.Thumbprint);
                                ////      File.WriteAllBytes(filename, certificate.Export(X509ContentType.Pkcs12, (string)null));
                                ////        certificate.Reset();  
                                ////        certificate = null;

                                //// 2021-01-04: If we want to do it, it would be:
                                //X509Certificate2 x509 = new X509Certificate2(cert.RawData);
                                //Convert.ToBase64String(x509.Export(X509ContentType.Pkcs12, (string)null));

                                store.Close();
                                store = null;

                                break;
                            }
                        }
                        certCollection.Clear();


                        if (store != null)
                        {
                            store.Close();
                            store = null;
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine("\r\n[X] An exception occurred {0}", ex.Message);
                }
            }

            return certificate;
        }


        public static Tuple<string, string> ParseDecCapiCertBlob(byte[] decBlobBytes)
        {
            // Parses a CAPI private key blob and turns it into a full RSA key we can use

            //https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/5cf2e6b9-3195-4f85-bc18-05b50e6d4e11?redirectedfrom=MSDN
            //http://www.turing321.com/hex_edit/hexprobe/binary_file.htm#Parse_Blobs
            //http://www.programmersought.com/article/9153121802/
            //https://docs.microsoft.com/en-us/windows/win32/seccrypto/base-provider-key-blobs?redirectedfrom=MSDN#public-key-blobs
            //https://www.sysadmins.lv/blog-en/how-to-convert-pem-to-x509certificate2-in-powershell-revisited.aspx
            //https://etherhack.co.uk/asymmetric/docs/rsa_key_breakdown.html
            //https://www.passcape.com/index.php?section=docsys&cmd=details&id=28

            var offset = 0;
            var magic = Encoding.UTF8.GetString(decBlobBytes, offset, 4);

            offset += 4;
            var len1 = BitConverter.ToInt32(decBlobBytes, offset);

            offset += 4;
            var bitlen = BitConverter.ToInt32(decBlobBytes, offset);
            var chunk = bitlen / 16;

            offset += 4;
            var unk = BitConverter.ToInt32(decBlobBytes, offset);

            offset += 4;
            var pubexp = new byte[4];
            Array.Copy(decBlobBytes, offset, pubexp, 0, 4);

            offset += 4;
            var modulus = new byte[chunk * 2];
            Array.Copy(decBlobBytes, offset, modulus, 0, chunk * 2);

            offset += len1;
            var prime1 = new byte[chunk];
            Array.Copy(decBlobBytes, offset, prime1, 0, chunk);

            offset += len1 / 2;
            var prime2 = new byte[chunk];
            Array.Copy(decBlobBytes, offset, prime2, 0, chunk);

            offset += len1 / 2;
            var exponent1 = new byte[chunk];
            Array.Copy(decBlobBytes, offset, exponent1, 0, chunk);
            
            offset += len1 / 2;
            var exponent2 = new byte[chunk];
            Array.Copy(decBlobBytes, offset, exponent2, 0, chunk);

            offset += len1 / 2;
            var coefficient = new byte[chunk];
            Array.Copy(decBlobBytes, offset, coefficient, 0, chunk);

            offset += len1 / 2;
            var privExponent = new byte[chunk * 2];
            Array.Copy(decBlobBytes, offset, privExponent, 0, chunk * 2);
            offset += len1;

            //http://blog.majcica.com/2011/12/03/certificates-to-db-and-back-part-2/
            //CspParameters parms = new CspParameters();
            //parms.Flags = CspProviderFlags.NoFlags;
            //parms.KeyContainerName = Guid.NewGuid().ToString().ToUpperInvariant();
            //parms.ProviderType = ((Environment.OSVersion.Version.Major > 5) || ((Environment.OSVersion.Version.Major == 5) && (Environment.OSVersion.Version.Minor >= 1))) ? 0x18 : 1;
            //RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(parms);

            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                RSAParameters RSAKeyInfo = new RSAParameters();
                string tmpStr = Helpers.OS2IP(modulus, false).ToHexString();
                int len = tmpStr.Length;

                RSAKeyInfo.Modulus = Helpers.PadToLength(Helpers.ConvertHexStringToByteArray(Helpers.OS2IP(modulus, true).ToHexString()));
                RSAKeyInfo.Exponent = Helpers.TrimByte(Helpers.ConvertHexStringToByteArray(Helpers.OS2IP(pubexp, true).ToHexString()));
                RSAKeyInfo.D = Helpers.PadToLength(Helpers.ConvertHexStringToByteArray(Helpers.OS2IP(privExponent, true).ToHexString()));
                RSAKeyInfo.P = Helpers.PadToLength(Helpers.ConvertHexStringToByteArray(Helpers.OS2IP(prime1, true).ToHexString()));
                RSAKeyInfo.Q = Helpers.PadToLength(Helpers.ConvertHexStringToByteArray(Helpers.OS2IP(prime2, true).ToHexString()));
                RSAKeyInfo.DP = Helpers.PadToLength(Helpers.ConvertHexStringToByteArray(Helpers.OS2IP(exponent1, true).ToHexString()));
                RSAKeyInfo.DQ = Helpers.PadToLength(Helpers.ConvertHexStringToByteArray(Helpers.OS2IP(exponent2, true).ToHexString()));
                RSAKeyInfo.InverseQ = Helpers.PadToLength(Helpers.ConvertHexStringToByteArray(Helpers.OS2IP(coefficient, true).ToHexString()));

                //Console.WriteLine($"\nModulus: {BitConverter.ToString(RSAKeyInfo.Modulus)}");
                //Console.WriteLine($"{modulus.Length}");
                //Console.WriteLine($"\nExponent: {BitConverter.ToString(RSAKeyInfo.Exponent)}");
                //Console.WriteLine($"{RSAKeyInfo.Exponent.Length}");
                //Console.WriteLine($"\nprivExponent: {BitConverter.ToString(privExponent)}");
                //Console.WriteLine($"{privExponent.Length}");
                //Console.WriteLine($"\nD: {BitConverter.ToString(RSAKeyInfo.D)}");
                //Console.WriteLine($"{RSAKeyInfo.D.Length}");
                //Console.WriteLine($"\nP: {BitConverter.ToString(RSAKeyInfo.P)}");
                //Console.WriteLine($"{RSAKeyInfo.P.Length}");
                //Console.WriteLine($"\nQ: {BitConverter.ToString(RSAKeyInfo.Q)}");
                //Console.WriteLine($"{RSAKeyInfo.Q.Length}");
                //Console.WriteLine($"\nDP: {BitConverter.ToString(RSAKeyInfo.DP)}");
                //Console.WriteLine($"{RSAKeyInfo.DP.Length}");
                //Console.WriteLine($"\nDQ: {BitConverter.ToString(RSAKeyInfo.DQ)}");
                //Console.WriteLine($"{RSAKeyInfo.DQ.Length}");
                //Console.WriteLine($"\nInverseQ: {BitConverter.ToString(RSAKeyInfo.InverseQ)}");
                //Console.WriteLine($"{RSAKeyInfo.InverseQ.Length}");

                rsa.ImportParameters(RSAKeyInfo);
                Tuple<string, string> privateKeyb64 = new Tuple<string, string>(Crypto.ExportPrivateKey(rsa), rsa.ToXmlString(true));

                return privateKeyb64;
            }
        }


        public static Tuple<string, string> ParseDecCngCertBlob(byte[] decBlobBytes)
        {
            // Parses a CNG BCRYPT_RSAKEY_BLOB blob and turns it into a full RSA key we can use

            // https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob?redirectedfrom=MSDN

            //typedef struct _BCRYPT_RSAKEY_BLOB {
            //  ULONG Magic;
            //  ULONG BitLength;
            //  ULONG cbPublicExp;
            //  ULONG cbModulus;
            //  ULONG cbPrime1;
            //  ULONG cbPrime2;
            //} BCRYPT_RSAKEY_BLOB;

            // Partial:
            //    BCRYPT_RSAKEY_BLOB
            //    PublicExponent[cbPublicExp] // Big-endian.
            //    Modulus[cbModulus] // Big-endian.
            //    Prime1[cbPrime1] // Big-endian.
            //    Prime2[cbPrime2] // Big-endian.

            // Full:
            //    BCRYPT_RSAKEY_BLOB
            //    PublicExponent[cbPublicExp] // Big-endian.
            //    Modulus[cbModulus] // Big-endian.
            //    Prime1[cbPrime1] // Big-endian.
            //    Prime2[cbPrime2] // Big-endian.
            //    Exponent1[cbPrime1] // Big-endian.
            //    Exponent2[cbPrime2] // Big-endian.
            //    Coefficient[cbPrime1] // Big-endian.
            //    PrivateExponent[cbModulus] // Big-endian.

            var offset = 0;
            var magic = Encoding.UTF8.GetString(decBlobBytes, offset, 4);
            //Console.WriteLine($"magic: {magic}");

            offset += 4;
            var bitlen = BitConverter.ToInt32(decBlobBytes, offset);
            var chunk = bitlen / 16;
            //Console.WriteLine($"bitlen: {bitlen}");
            //Console.WriteLine($"chunk: {chunk}");

            offset += 4;
            var cbPublicExp = BitConverter.ToInt32(decBlobBytes, offset);
            //Console.WriteLine($"cbPublicExp: {cbPublicExp}");

            offset += 4;
            var cbModulus = BitConverter.ToInt32(decBlobBytes, offset);
            //Console.WriteLine($"cbModulus: {cbModulus}");

            offset += 4;
            var cbPrime1 = BitConverter.ToInt32(decBlobBytes, offset);
            //Console.WriteLine($"cbPrime1: {cbPrime1}");

            offset += 4;
            var cbPrime2 = BitConverter.ToInt32(decBlobBytes, offset);
            //Console.WriteLine($"cbPrime2: {cbPrime2}");

            offset += 4;
            var pubexp = new byte[cbPublicExp];
            Array.Copy(decBlobBytes, offset, pubexp, 0, cbPublicExp);
            //Console.WriteLine($"\npubexp: {BitConverter.ToString(pubexp)}");

            offset += cbPublicExp;
            var modulus = new byte[cbModulus];
            Array.Copy(decBlobBytes, offset, modulus, 0, cbModulus);
            //Console.WriteLine($"\nmodulus: {BitConverter.ToString(modulus)}");

            offset += cbModulus;
            var prime1 = new byte[cbPrime1];
            Array.Copy(decBlobBytes, offset, prime1, 0, cbPrime1);
            //Console.WriteLine($"\nprime1: {BitConverter.ToString(prime1)}");

            offset += cbPrime1;
            var prime2 = new byte[cbPrime2];
            Array.Copy(decBlobBytes, offset, prime2, 0, cbPrime2);
            //Console.WriteLine($"\nprime2: {BitConverter.ToString(prime2)}");

            offset += cbPrime2;
            var exponent1 = new byte[cbPrime1];
            Array.Copy(decBlobBytes, offset, exponent1, 0, cbPrime1);
            //Console.WriteLine($"\nexponent1: {BitConverter.ToString(exponent1)}");

            offset += cbPrime1;
            var exponent2 = new byte[cbPrime2];
            Array.Copy(decBlobBytes, offset, exponent2, 0, cbPrime2);
            //Console.WriteLine($"\nexponent2: {BitConverter.ToString(exponent2)}");

            offset += cbPrime2;
            var coefficient = new byte[cbPrime1];
            Array.Copy(decBlobBytes, offset, coefficient, 0, cbPrime1);
            //Console.WriteLine($"\ncoefficient: {BitConverter.ToString(coefficient)}");

            offset += cbPrime1;
            var privExponent = new byte[cbModulus];
            Array.Copy(decBlobBytes, offset, privExponent, 0, cbModulus);
            //Console.WriteLine($"\nprivExponent: {BitConverter.ToString(privExponent)}");

            //http://blog.majcica.com/2011/12/03/certificates-to-db-and-back-part-2/
            //CspParameters parms = new CspParameters();
            //parms.Flags = CspProviderFlags.NoFlags;
            //parms.KeyContainerName = Guid.NewGuid().ToString().ToUpperInvariant();
            //parms.ProviderType = ((Environment.OSVersion.Version.Major > 5) || ((Environment.OSVersion.Version.Major == 5) && (Environment.OSVersion.Version.Minor >= 1))) ? 0x18 : 1;
            //RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(parms);

            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                RSAParameters RSAKeyInfo = new RSAParameters();
                string tmpStr = Helpers.OS2IP(modulus, false).ToHexString();
                int len = tmpStr.Length;

                RSAKeyInfo.Modulus = Helpers.PadToLength(Helpers.ConvertHexStringToByteArray(Helpers.OS2IP(modulus, false).ToHexString()));
                RSAKeyInfo.Exponent = Helpers.TrimByte(Helpers.ConvertHexStringToByteArray(Helpers.OS2IP(pubexp, false).ToHexString()));
                RSAKeyInfo.D = Helpers.PadToLength(Helpers.ConvertHexStringToByteArray(Helpers.OS2IP(privExponent, false).ToHexString()));
                RSAKeyInfo.P = Helpers.PadToLength(Helpers.ConvertHexStringToByteArray(Helpers.OS2IP(prime1, false).ToHexString()));
                RSAKeyInfo.Q = Helpers.PadToLength(Helpers.ConvertHexStringToByteArray(Helpers.OS2IP(prime2, false).ToHexString()));
                RSAKeyInfo.DP = Helpers.PadToLength(Helpers.ConvertHexStringToByteArray(Helpers.OS2IP(exponent1, false).ToHexString()));
                RSAKeyInfo.DQ = Helpers.PadToLength(Helpers.ConvertHexStringToByteArray(Helpers.OS2IP(exponent2, false).ToHexString()));
                RSAKeyInfo.InverseQ = Helpers.PadToLength(Helpers.ConvertHexStringToByteArray(Helpers.OS2IP(coefficient, false).ToHexString()));

                //Console.WriteLine($"\nModulus: {BitConverter.ToString(RSAKeyInfo.Modulus)}");
                //Console.WriteLine($"{modulus.Length}");
                //Console.WriteLine($"\nExponent: {BitConverter.ToString(RSAKeyInfo.Exponent)}");
                //Console.WriteLine($"{RSAKeyInfo.Exponent.Length}");
                //Console.WriteLine($"\nprivExponent: {BitConverter.ToString(privExponent)}");
                //Console.WriteLine($"{privExponent.Length}");
                //Console.WriteLine($"\nD: {BitConverter.ToString(RSAKeyInfo.D)}");
                //Console.WriteLine($"{RSAKeyInfo.D.Length}");
                //Console.WriteLine($"\nP: {BitConverter.ToString(RSAKeyInfo.P)}");
                //Console.WriteLine($"{RSAKeyInfo.P.Length}");
                //Console.WriteLine($"\nQ: {BitConverter.ToString(RSAKeyInfo.Q)}");
                //Console.WriteLine($"{RSAKeyInfo.Q.Length}");
                //Console.WriteLine($"\nDP: {BitConverter.ToString(RSAKeyInfo.DP)}");
                //Console.WriteLine($"{RSAKeyInfo.DP.Length}");
                //Console.WriteLine($"\nDQ: {BitConverter.ToString(RSAKeyInfo.DQ)}");
                //Console.WriteLine($"{RSAKeyInfo.DQ.Length}");
                //Console.WriteLine($"\nInverseQ: {BitConverter.ToString(RSAKeyInfo.InverseQ)}");
                //Console.WriteLine($"{RSAKeyInfo.InverseQ.Length}");

                rsa.ImportParameters(RSAKeyInfo);

                Tuple<string, string> privateKeyb64 = new Tuple<string, string>(Crypto.ExportPrivateKey(rsa), rsa.ToXmlString(true));

                return privateKeyb64;
            }
        }


        public static Dictionary<string, string> PVKTriage(Dictionary<string, string> arguments)
        {
            // used by command functions to take a /pvk:X backupkey and use it to decrypt user masterkeys
            var masterkeys = new Dictionary<string, string>();

            var pvk64 = arguments["/pvk"];
            if (String.IsNullOrEmpty(pvk64))
            {
                Console.WriteLine("[X] /pvk:X must be a .pvk file or base64 encoded pvk representation");
                return masterkeys;
            }
            byte[] backupKeyBytes;

            if (File.Exists(pvk64))
            {
                backupKeyBytes = File.ReadAllBytes(pvk64);
            }
            else
            {
                try
                {
                    backupKeyBytes = Convert.FromBase64String(pvk64);
                }
                catch
                {
                    Console.WriteLine("[X] Error base64 decoding /pvk:X !");
                    return masterkeys;
                }
            }

            Console.WriteLine("[*] Using a domain DPAPI backup key to triage masterkeys for decryption key mappings!");

            if (arguments.ContainsKey("/server"))
            {
                masterkeys = Triage.TriageUserMasterKeys(backupKeyBytes, false, arguments["/server"]);
            }
            else
            {
                Console.WriteLine("");
                masterkeys = Triage.TriageUserMasterKeys(backupKeyBytes, false);
            }

            if (masterkeys.Count == 0)
            {
                Console.WriteLine("[!] No master keys decrypted!\r\n");
            }
            else
            {
                Console.WriteLine("[*] User master key cache:\r\n");
                foreach (var kvp in masterkeys)
                {
                    Console.WriteLine("{0}:{1}", kvp.Key, kvp.Value);
                }
                Console.WriteLine();
            }

            return masterkeys;
        }


        public static byte[] DescribeDPAPIBlob(byte[] blobBytes, Dictionary<string, string> MasterKeys, string blobType = "credential", bool unprotect = false, byte[] entropy = null)
        {
            // parses a DPAPI credential or vault policy blob, also returning the decrypted blob plaintext

            // credentialBytes  ->  byte array of the credential file
            // MasterKeys       ->  dictionary of GUID:Sha1(MasterKey) mappings for decryption
            // blobType         ->  "credential", vault "policy", "blob", "rdg", "keepass", or "chrome"

            var offset = 0;
            if (blobType.Equals("credential"))
            {
                offset = 36;
            }
            else if (blobType.Equals("policy") || blobType.Equals("blob") || blobType.Equals("rdg") || blobType.Equals("chrome") || blobType.Equals("keepass"))
            {
                offset = 24;
            }
            else
            {
                Console.WriteLine("[X] Unsupported blob type: {0}", blobType);
                return new byte[0];
            }

            var guidMasterKeyBytes = new byte[16];
            Array.Copy(blobBytes, offset, guidMasterKeyBytes, 0, 16);
            var guidMasterKey = new Guid(guidMasterKeyBytes);
            var guidString = $"{{{guidMasterKey}}}";
            if (!blobType.Equals("rdg") && !blobType.Equals("chrome"))
            {
                Console.WriteLine("    guidMasterKey    : {0}", guidString);
            }
            offset += 16;

            if (!blobType.Equals("rdg") && !blobType.Equals("chrome"))
            {
                Console.WriteLine("    size             : {0}", blobBytes.Length);
            }

            var flags = BitConverter.ToUInt32(blobBytes, offset);
            offset += 4;
            if (!blobType.Equals("rdg") && !blobType.Equals("chrome"))
            {
                Console.Write("    flags            : 0x{0}", flags.ToString("X"));
                if ((flags != 0) && ((flags & 0x20000000) == flags))
                {
                    Console.Write(" (CRYPTPROTECT_SYSTEM)");
                }
                Console.WriteLine();
            }

            var descLength = BitConverter.ToInt32(blobBytes, offset);
            offset += 4;
            var description = Encoding.Unicode.GetString(blobBytes, offset, descLength);
            offset += descLength;

            var algCrypt = BitConverter.ToInt32(blobBytes, offset);
            offset += 4;

            var algCryptLen = BitConverter.ToInt32(blobBytes, offset);
            offset += 4;

            var saltLen = BitConverter.ToInt32(blobBytes, offset);
            offset += 4;

            var saltBytes = new byte[saltLen];
            Array.Copy(blobBytes, offset, saltBytes, 0, saltLen);
            offset += saltLen;

            var hmacKeyLen = BitConverter.ToInt32(blobBytes, offset);
            offset += 4 + hmacKeyLen;

            var algHash = BitConverter.ToInt32(blobBytes, offset);
            offset += 4;

            if (!blobType.Equals("rdg") && !blobType.Equals("chrome"))
            {
                Console.WriteLine("    algHash/algCrypt : {0} ({1}) / {2} ({3})", algHash, (Interop.CryptAlg)algHash, algCrypt, (Interop.CryptAlg)algCrypt);
                Console.WriteLine("    description      : {0}", description);
            }

            var algHashLen = BitConverter.ToInt32(blobBytes, offset);
            offset += 4;

            var hmac2KeyLen = BitConverter.ToInt32(blobBytes, offset);
            offset += 4 + hmac2KeyLen;

            var dataLen = BitConverter.ToInt32(blobBytes, offset);
            offset += 4;
            var dataBytes = new byte[dataLen];
            Array.Copy(blobBytes, offset, dataBytes, 0, dataLen);

            if ((blobType.Equals("rdg") || blobType.Equals("blob") || blobType.Equals("chrome") || blobType.Equals("keepass")) && unprotect)
            {
                // use CryptUnprotectData()
                try
                {
                    var decBytes = ProtectedData.Unprotect(blobBytes, entropy, DataProtectionScope.CurrentUser);
                    return decBytes;
                }
                catch
                {
                    return Encoding.Unicode.GetBytes($"MasterKey needed - {guidString}");
                }
            }

            if (MasterKeys.ContainsKey(guidString))
            {
                // if this key is present, decrypt this blob
                if (algHash == 32782)
                {
                    // grab the sha1(masterkey) from the cache
                    try
                    {
                        var keyBytes = Helpers.StringToByteArray(MasterKeys[guidString].ToString());

                        // derive the session key
                        var derivedKeyBytes = Crypto.DeriveKey(keyBytes, saltBytes, algHash, entropy);
                        var finalKeyBytes = new byte[algCryptLen / 8];
                        Array.Copy(derivedKeyBytes, finalKeyBytes, algCryptLen / 8);

                        // decrypt the blob with the session key
                        if (blobType.Equals("chrome"))
                        {
                            return Crypto.DecryptBlob(dataBytes, finalKeyBytes, algCrypt, PaddingMode.PKCS7);
                        }
                        else
                        {
                            return Crypto.DecryptBlob(dataBytes, finalKeyBytes, algCrypt);
                        }
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine("    [X] Error retrieving GUID:SHA1 from cache {0} : {1}", guidString, e.Message);
                    }
                }
                else if (algHash == 32772)
                {
                    try
                    {
                        // grab the sha1(masterkey) from the cache
                        var keyBytes = Helpers.StringToByteArray(MasterKeys[guidString].ToString());

                        // derive the session key
                        var derivedKeyBytes = Crypto.DeriveKey(keyBytes, saltBytes, algHash, entropy);
                        var finalKeyBytes = new byte[algCryptLen / 8];
                        Array.Copy(derivedKeyBytes, finalKeyBytes, algCryptLen / 8);

                        // decrypt the blob with the session key
                        if (blobType.Equals("chrome"))
                        {
                            return Crypto.DecryptBlob(dataBytes, finalKeyBytes, algCrypt, PaddingMode.PKCS7);
                        }
                        else
                        {
                            return Crypto.DecryptBlob(dataBytes, finalKeyBytes, algCrypt);
                        }
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine("    [X] Error retrieving GUID:SHA1 from cache {0} : {1}", guidString, e.Message);
                    }
                }
                else
                {
                    Console.WriteLine("    [X] Only sha1 and sha256 are currently supported for the hash algorithm. Alg '{0}' ({1}) not supported", algHash, (Interop.CryptAlg)algHash);
                }
            }
            else
            {
                if (blobType.Equals("rdg"))
                {
                    return Encoding.Unicode.GetBytes($"MasterKey needed - {guidString}");
                }
                else if (blobType.Equals("chrome"))
                {
                    return Encoding.ASCII.GetBytes($"MasterKey needed - {guidString}");
                }
                else
                {
                    Console.WriteLine("    [X] MasterKey GUID not in cache: {0}", guidString);
                }
            }

            if (!blobType.Equals("rdg") && !blobType.Equals("chrome"))
            {
                Console.WriteLine();
            }

            return new byte[0];
        }


        public static ArrayList DescribeVaultPolicy(byte[] policyBytes, Dictionary<string, string> MasterKeys)
        {
            // parses a vault policy file, attempting to decrypt if possible
            // a two-valued arraylist of the aes128/aes256 keys is returned if decryption is successful

            // from https://github.com/gentilkiwi/mimikatz/blob/110a831ebe7b529c5dd3010f9e7fced0d3e3a46c/modules/kull_m_cred.h#L111-L131
            /*
               typedef struct _KULL_M_CRED_VAULT_POLICY_KEY {
	                GUID unk0;
	                GUID unk1;
	                DWORD dwKeyBlob;
	                PVOID KeyBlob;
                } KULL_M_CRED_VAULT_POLICY_KEY, *PKULL_M_CRED_VAULT_POLICY_KEY;

                typedef struct _KULL_M_CRED_VAULT_POLICY {
	                DWORD version;
	                GUID vault;

	                DWORD dwName;
	                LPWSTR Name;

	                DWORD unk0;
	                DWORD unk1;
	                DWORD unk2;

	                DWORD dwKey;
	                PKULL_M_CRED_VAULT_POLICY_KEY key;
                } KULL_M_CRED_VAULT_POLICY, *PKULL_M_CRED_VAULT_POLICY;
            */

            var offset = 0;

            var version = BitConverter.ToInt32(policyBytes, offset);
            offset += 4;

            var vaultIDbytes = new byte[16];
            Array.Copy(policyBytes, offset, vaultIDbytes, 0, 16);
            var vaultID = new Guid(vaultIDbytes);
            offset += 16;

            Console.WriteLine("\r\n  VaultID            : {0}", vaultID);

            var nameLen = BitConverter.ToInt32(policyBytes, offset);
            offset += 4;
            var name = Encoding.Unicode.GetString(policyBytes, offset, nameLen);
            offset += nameLen;
            Console.WriteLine("  Name               : {0}", name);

            // skip unk0/unk1/unk2
            offset += 12;

            var keyLen = BitConverter.ToInt32(policyBytes, offset);
            offset += 4;

            // skip unk0/unk1 GUIDs
            offset += 32;

            var keyBlobLen = BitConverter.ToInt32(policyBytes, offset);
            offset += 4;

            // extract out the DPAPI blob
            var blobBytes = new byte[keyBlobLen];
            Array.Copy(policyBytes, offset, blobBytes, 0, keyBlobLen);

            // 24 -> offset where the masterkey GUID starts
            var plaintextBytes = DescribeDPAPIBlob(blobBytes, MasterKeys, "policy");

            if (plaintextBytes.Length > 0)
            {
                var keys = ParseDecPolicyBlob(plaintextBytes);

                if (keys.Count == 2)
                {
                    var aes128KeyStr = BitConverter.ToString((byte[])keys[0]).Replace("-", "");
                    Console.WriteLine("    aes128 key       : {0}", aes128KeyStr);

                    var aes256KeyStr = BitConverter.ToString((byte[])keys[1]).Replace("-", "");
                    Console.WriteLine("    aes256 key       : {0}", aes256KeyStr);

                    return keys;
                }
                else
                {
                    Console.WriteLine("    [X] Error parsing decrypted Policy.vpol (AES keys not extracted, likely incorrect password for the associated masterkey)");
                    return new ArrayList();
                }
            }
            else
            {
                return new ArrayList();
            }
        }

        public static void DescribeVaultCred(byte[] vaultBytes, ArrayList AESKeys)
        {
            // parses a vault credential file and displays data, attempting to decrypt if the necessary AES keys are supplied

            // from https://github.com/gentilkiwi/mimikatz/blob/110a831ebe7b529c5dd3010f9e7fced0d3e3a46c/modules/kull_m_cred.h#L139-L154
            /*
                typedef struct _KULL_M_CRED_VAULT_CREDENTIAL {
	                GUID SchemaId;
	                DWORD unk0; // 4
	                FILETIME LastWritten;
	                DWORD unk1; // ffffffff
	                DWORD unk2; // flags ?

	                DWORD dwFriendlyName;
	                LPWSTR FriendlyName;
	
	                DWORD dwAttributesMapSize;
	                PKULL_M_CRED_VAULT_CREDENTIAL_ATTRIBUTE_MAP attributesMap;

	                DWORD __cbElements;
	                PKULL_M_CRED_VAULT_CREDENTIAL_ATTRIBUTE *attributes;
                } KULL_M_CRED_VAULT_CREDENTIAL, *PKULL_M_CRED_VAULT_CREDENTIAL;
            */

            var aes128key = (byte[])AESKeys[0];
            var aes256key = (byte[])AESKeys[1];

            var offset = 0;
            var finalAttributeOffset = 0;

            // skip the schema GUID
            offset += 16;

            var unk0 = BitConverter.ToInt32(vaultBytes, offset);
            offset += 4;

            var lastWritten = (long)BitConverter.ToInt64(vaultBytes, offset);
            offset += 8;
            var lastWrittenTime = DateTime.FromFileTime(lastWritten);
            Console.WriteLine("\r\n    LastWritten      : {0}", lastWrittenTime);

            // skip unk1/unk2
            offset += 8;

            var friendlyNameLen = BitConverter.ToInt32(vaultBytes, offset);
            offset += 4;

            var friendlyName = Encoding.Unicode.GetString(vaultBytes, offset, friendlyNameLen);
            offset += friendlyNameLen;
            Console.WriteLine("    FriendlyName     : {0}", friendlyName);

            var attributeMapLen = BitConverter.ToInt32(vaultBytes, offset);
            offset += 4;

            // https://github.com/gentilkiwi/mimikatz/blob/110a831ebe7b529c5dd3010f9e7fced0d3e3a46c/modules/kull_m_cred.h#L133-L137
            /*
                typedef struct _KULL_M_CRED_VAULT_CREDENTIAL_ATTRIBUTE_MAP {
	                DWORD id;
	                DWORD offset; //maybe 64
	                DWORD unk;
                } KULL_M_CRED_VAULT_CREDENTIAL_ATTRIBUTE_MAP
             */

            var numberOfAttributes = attributeMapLen / 12;

            var attributeMap = new Dictionary<int, int>();

            for (var i = 0; i < numberOfAttributes; ++i)
            {
                var attributeNum = BitConverter.ToInt32(vaultBytes, offset);
                offset += 4;
                var attributeOffset = BitConverter.ToInt32(vaultBytes, offset);
                offset += 8; // skip unk

                attributeMap.Add(attributeNum, attributeOffset);
            }

            var leftover = new byte[vaultBytes.Length - 222];
            Array.Copy(vaultBytes, 222, leftover, 0, leftover.Length);

            foreach (var attribute in attributeMap)
            {
                // from https://github.com/gentilkiwi/mimikatz/blob/110a831ebe7b529c5dd3010f9e7fced0d3e3a46c/modules/kull_m_cred.h#L12-L22
                /*
                    typedef struct _KULL_M_CRED_VAULT_CREDENTIAL_ATTRIBUTE {
	                    DWORD id;
	                    DWORD unk0; // maybe flags
	                    DWORD unk1; // maybe type
	                    DWORD unk2; // 0a 00 00 00
	                    //DWORD unkComplex; // only in complex (and 0, avoid it ?)
	                    DWORD szData; // when parsing, inc bullshit... clean in structure
	                    PBYTE data;
	                    DWORD szIV;
	                    PBYTE IV;
                    } KULL_M_CRED_VAULT_CREDENTIAL_ATTRIBUTE, *PKULL_M_CRED_VAULT_CREDENTIAL_ATTRIBUTE;
                */

                // initial offset
                var attributeOffset = attribute.Value;

                // skip cruft
                attributeOffset += 16;

                if (attribute.Key >= 100)
                {
                    attributeOffset += 4; // id100 https://github.com/SecureAuthCorp/impacket/blob/13a65706273680c297caee0211460ef7369aa8ca/impacket/dpapi.py#L551-L552
                }

                var dataLen = BitConverter.ToInt32(vaultBytes, attributeOffset);
                attributeOffset += 4;

                finalAttributeOffset = attributeOffset;

                if (dataLen > 0)
                {
                    var IVPresent = BitConverter.ToBoolean(vaultBytes, attributeOffset);
                    attributeOffset += 1;

                    if (!IVPresent)
                    {
                        // we don't really care about these... do we?
                        var dataBytes = new byte[dataLen - 1];

                        // use aes128, no IV
                        Array.Copy(vaultBytes, attributeOffset, dataBytes, 0, dataLen - 1);

                        finalAttributeOffset = attributeOffset + dataLen - 1;

                        var decBytes = Crypto.AESDecrypt(aes128key, new byte[0], dataBytes);
                    }
                    else
                    {
                        // use aes256 w/ IV

                        var IVLen = BitConverter.ToInt32(vaultBytes, attributeOffset);
                        attributeOffset += 4;

                        var IVBytes = new byte[IVLen];
                        Array.Copy(vaultBytes, attributeOffset, IVBytes, 0, IVLen);
                        attributeOffset += IVLen;

                        var dataBytes = new byte[dataLen - 1 - 4 - IVLen];
                        Array.Copy(vaultBytes, attributeOffset, dataBytes, 0, dataLen - 1 - 4 - IVLen);
                        attributeOffset += dataLen - 1 - 4 - IVLen;
                        finalAttributeOffset = attributeOffset;

                        var decBytes = Crypto.AESDecrypt(aes256key, IVBytes, dataBytes);

                        DescribeVaultItem(decBytes);
                    }
                }
            }

            if ((numberOfAttributes > 0) && (unk0 < 4))
            {
                // bullshit vault credential clear attributes...

                var clearOffset = finalAttributeOffset - 2;
                var clearBytes = new byte[vaultBytes.Length - clearOffset];
                Array.Copy(vaultBytes, clearOffset, clearBytes, 0, clearBytes.Length);

                var cleatOffSet2 = 0;
                cleatOffSet2 += 4; // skip ID

                var dataLen = BitConverter.ToInt32(clearBytes, cleatOffSet2);
                cleatOffSet2 += 4;

                if (dataLen > 2000)
                {
                    Console.WriteLine("    [*] Vault credential clear attribute is > 2000 bytes, skipping...");
                }

                else if (dataLen > 0)
                {
                    var IVPresent = BitConverter.ToBoolean(vaultBytes, cleatOffSet2);
                    cleatOffSet2 += 1;

                    if (!IVPresent)
                    {
                        // we don't really care about these... do we?
                        var dataBytes = new byte[dataLen - 1];

                        // use aes128, no IV
                        Array.Copy(clearBytes, cleatOffSet2, dataBytes, 0, dataLen - 1);

                        var decBytes = Crypto.AESDecrypt(aes128key, new byte[0], dataBytes);
                    }
                    else
                    {
                        // use aes256 w/ IV
                        var IVLen = BitConverter.ToInt32(clearBytes, cleatOffSet2);
                        cleatOffSet2 += 4;

                        var IVBytes = new byte[IVLen];
                        Array.Copy(clearBytes, cleatOffSet2, IVBytes, 0, IVLen);
                        cleatOffSet2 += IVLen;

                        var dataBytes = new byte[dataLen - 1 - 4 - IVLen];
                        Array.Copy(clearBytes, cleatOffSet2, dataBytes, 0, dataLen - 1 - 4 - IVLen);
                        cleatOffSet2 += dataLen - 1 - 4 - IVLen;
                        finalAttributeOffset = cleatOffSet2;

                        var decBytes = Crypto.AESDecrypt(aes256key, IVBytes, dataBytes);

                        DescribeVaultItem(decBytes);
                    }
                }
            }
        }

        public static void DescribeVaultItem(byte[] vaultItemBytes)
        {
            // describes/parses a single vault item

            // https://github.com/gentilkiwi/mimikatz/blob/110a831ebe7b529c5dd3010f9e7fced0d3e3a46c/modules/kull_m_cred.h#L156-L167

            /*
                typedef struct _KULL_M_CRED_VAULT_CLEAR_ENTRY {
	                DWORD id;
	                DWORD size;
	                BYTE data[ANYSIZE_ARRAY];
                } KULL_M_CRED_VAULT_CLEAR_ENTRY, *PKULL_M_CRED_VAULT_CLEAR_ENTRY;

                typedef struct _KULL_M_CRED_VAULT_CLEAR {
	                DWORD version;
	                DWORD count;
	                DWORD unk;
	                PKULL_M_CRED_VAULT_CLEAR_ENTRY *entries;
                } KULL_M_CRED_VAULT_CLEAR, *PKULL_M_CRED_VAULT_CLEAR;
             */

            var offset = 0;

            var version = BitConverter.ToInt32(vaultItemBytes, offset);
            offset += 4;

            var count = BitConverter.ToInt32(vaultItemBytes, offset);
            offset += 4;

            // skip unk
            offset += 4;

            for (var i = 0; i < count; ++i)
            {
                var id = BitConverter.ToInt32(vaultItemBytes, offset);
                offset += 4;

                var size = BitConverter.ToInt32(vaultItemBytes, offset);
                offset += 4;

                var entryString = Encoding.Unicode.GetString(vaultItemBytes, offset, size);
                var entryData = new byte[size];
                Array.Copy(vaultItemBytes, offset, entryData, 0, size);

                offset += size;

                switch (id)
                {
                    case 1:
                        Console.WriteLine("    Resource         : {0}", entryString);
                        break;
                    case 2:
                        Console.WriteLine("    Identity         : {0}", entryString);
                        break;
                    case 3:
                        Console.WriteLine("    Authenticator    : {0}", entryString);
                        break;
                    default:
                        if (Helpers.IsUnicode(entryData))
                        {
                            Console.WriteLine("    Property {0}     : {1}", id, entryString);
                        }
                        else
                        {
                            var entryDataString = BitConverter.ToString(entryData).Replace("-", " ");
                            Console.WriteLine("    Property {0}     : {1}", id, entryDataString);
                        }
                        break;
                }
            }
        }

        public static void DescribeCredential(byte[] credentialBytes, Dictionary<string, string> MasterKeys)
        {
            // try to decrypt the credential blob, displaying if successful
            var plaintextBytes = DescribeDPAPIBlob(credentialBytes, MasterKeys, "credential");
            if (plaintextBytes.Length > 0)
            {
                ParseDecCredBlob(plaintextBytes);
            }
        }

        public static void ParseDecCredBlob(byte[] decBlobBytes)
        {
            // parse/display a decrypted credential blob

            var offset = 0;

            var credFlags = BitConverter.ToUInt32(decBlobBytes, offset);
            offset += 4;
            var credSize = BitConverter.ToUInt32(decBlobBytes, offset);
            offset += 4;
            var credUnk0 = BitConverter.ToUInt32(decBlobBytes, offset);
            offset += 4;
            var type = BitConverter.ToUInt32(decBlobBytes, offset);
            offset += 4;
            var flags = BitConverter.ToUInt32(decBlobBytes, offset);
            offset += 4;

            var lastWritten = (long)BitConverter.ToInt64(decBlobBytes, offset);
            offset += 8;
            var lastWrittenTime = new DateTime();
            try
            {
                // sanity check that decrypytion worked correctly
                lastWrittenTime = DateTime.FromFileTime(lastWritten);
                if ((lastWrittenTime < DateTime.Now.AddYears(-20)) || (lastWrittenTime > DateTime.Now.AddYears(1)))
                {
                    Console.WriteLine("    [X] Decryption failed, likely incorrect password for the associated masterkey");
                    return;
                }
            }
            catch
            {
                Console.WriteLine("    [X] Decryption failed, likely incorrect password for the associated masterkey");
                return;
            }
            Console.WriteLine("    LastWritten      : {0}", lastWrittenTime);

            var unkFlagsOrSize = BitConverter.ToUInt32(decBlobBytes, offset);
            offset += 4;
            var persist = BitConverter.ToUInt32(decBlobBytes, offset);
            offset += 4;
            var attributeCount = BitConverter.ToUInt32(decBlobBytes, offset);
            offset += 4;
            var unk0 = BitConverter.ToUInt32(decBlobBytes, offset);
            offset += 4;
            var unk1 = BitConverter.ToUInt32(decBlobBytes, offset);
            offset += 4;

            var targetNameLen = BitConverter.ToInt32(decBlobBytes, offset);
            offset += 4;
            var targetName = Encoding.Unicode.GetString(decBlobBytes, offset, targetNameLen);
            offset += targetNameLen;
            Console.WriteLine("    TargetName       : {0}", targetName.Trim());

            var targetAliasLen = BitConverter.ToInt32(decBlobBytes, offset);
            offset += 4;
            var targetAlias = Encoding.Unicode.GetString(decBlobBytes, offset, targetAliasLen);
            offset += targetAliasLen;
            Console.WriteLine("    TargetAlias      : {0}", targetAlias.Trim());

            var commentLen = BitConverter.ToInt32(decBlobBytes, offset);
            offset += 4;
            var comment = Encoding.Unicode.GetString(decBlobBytes, offset, commentLen);
            offset += commentLen;
            Console.WriteLine("    Comment          : {0}", comment.Trim());

            var unkDataLen = BitConverter.ToInt32(decBlobBytes, offset);
            offset += 4;
            var unkData = Encoding.Unicode.GetString(decBlobBytes, offset, unkDataLen);
            offset += unkDataLen;

            var userNameLen = BitConverter.ToInt32(decBlobBytes, offset);
            offset += 4;
            var userName = Encoding.Unicode.GetString(decBlobBytes, offset, userNameLen);
            offset += userNameLen;
            Console.WriteLine("    UserName         : {0}", userName.Trim());

            var credBlobLen = BitConverter.ToInt32(decBlobBytes, offset);
            offset += 4;
            var credBlobBytes = new byte[credBlobLen];
            Array.Copy(decBlobBytes, offset, credBlobBytes, 0, credBlobLen);
            offset += credBlobLen;

            if (Helpers.IsUnicode(credBlobBytes))
            {
                var credBlob = Encoding.Unicode.GetString(credBlobBytes);
                Console.WriteLine("    Credential       : {0}", credBlob.Trim());
            }
            else
            {
                var credBlobByteString = BitConverter.ToString(credBlobBytes).Replace("-", " ");
                Console.WriteLine("    Credential       : {0}", credBlobByteString.Trim());
            }
        }

        public static ArrayList ParseDecPolicyBlob(byte[] decBlobBytes)
        {
            // parse a decrypted policy blob, returning an arraylist of the AES 128/256 keys

            var keys = new ArrayList();
            var s = Encoding.ASCII.GetString(decBlobBytes, 12, 4);

            if (s.Equals("KDBM"))
            {
                // https://github.com/gentilkiwi/mimikatz/blob/110a831ebe7b529c5dd3010f9e7fced0d3e3a46c/modules/kull_m_cred.h#L211-L227
                /*
                24 00 00 00
	                01 00 00 00
	                02 00 00 00
	                4b 44 42 4d KDBM 'MBDK'
	                01 00 00 00
	                10 00 00 00
		                xx xx xx (16)
                34 00 00 00
	                01 00 00 00
	                01 00 00 00
	                4b 44 42 4d KDBM 'MBDK'
	                01 00 00 00
	                20 00 00 00
		                xx xx xx (32)
                */

                var offset = 20;

                var aes128len = BitConverter.ToInt32(decBlobBytes, offset);
                offset += 4;

                if (aes128len != 16)
                {
                    Console.WriteLine("    [X] Error parsing decrypted Policy.vpol (aes128len != 16)");
                    return keys;
                }

                var aes128Key = new byte[aes128len];
                Array.Copy(decBlobBytes, offset, aes128Key, 0, aes128len);
                offset += aes128len;
                var aes128KeyStr = BitConverter.ToString(aes128Key).Replace("-", "");

                // skip more header stuff
                offset += 20;

                var aes256len = BitConverter.ToInt32(decBlobBytes, offset);
                offset += 4;

                if (aes256len != 32)
                {
                    Console.WriteLine("    [X] Error parsing decrypted Policy.vpol (aes256len != 32)");
                    return keys;
                }

                var aes256Key = new byte[aes256len];
                Array.Copy(decBlobBytes, offset, aes256Key, 0, aes256len);
                var aes256KeyStr = BitConverter.ToString(aes256Key).Replace("-", "");

                keys.Add(aes128Key);
                keys.Add(aes256Key);
            }
            else
            {
                var offset = 16;
                var s2 = Encoding.ASCII.GetString(decBlobBytes, offset, 4);
                offset += 4;

                if (s2.Equals("KSSM"))
                {
                    // thank you @gentilkiwi :pray:
                    // https://github.com/gentilkiwi/mimikatz/blob/110a831ebe7b529c5dd3010f9e7fced0d3e3a46c/modules/kull_m_cred.h#L238-L279
                    /*
                    38 02 00 00
	                    01 00 00 00
	                    02 00 00 00
	                    30 02 00 00
		                    4b 53 53 4d KSSM	'MSSK'
		                    02 00 01 00
		                    01 00 00 00
		                    10 00 00 00
		                    80 00 00 00 (128)
		
		                    10 00 00 00
			                    xx xx xx (16)
		                    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
		                    xx xx xx (16)
		                    yy yy yy (..)
		                    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
		                    a0 00 00 00
		                    40 01 00 00
		                    00 00 00 00 00 00 00 00 00 00 00 00
		                    00 00 00 00 00 00 00 00 00 00 00 00
                    38 02 00 00
	                    01 00 00 00
	                    01 00 00 00
	                    30 02 00 00
		                    4b 53 53 4d KSSM	'MSSK'
		                    02 00 01 00
		                    01 00 00 00
		                    10 00 00 00
		                    00 01 00 00 (256)
		                    20 00 00 00 (32)
			                    xx xx xx (32)
		                    00 00 00 00
		                    xx xx xx (32)
		                    yy yy yy (..)
		                    e0 00 00 00
		                    c0 01 00 00
		                    00 00 00 00 00 00 00 00 00 00 00 00
		                    00 00 00 00 00 00 00 00 00 00 00 00
                    */

                    // skip
                    offset += 16;

                    var aes128len = BitConverter.ToInt32(decBlobBytes, offset);
                    offset += 4;

                    if (aes128len != 16)
                    {
                        Console.WriteLine("    [X] Error parsing decrypted Policy.vpol (aes128len != 16)");
                        return keys;
                    }

                    var aes128Key = new byte[aes128len];
                    Array.Copy(decBlobBytes, offset, aes128Key, 0, aes128len);
                    offset += aes128len;
                    var aes128KeyStr = BitConverter.ToString(aes128Key).Replace("-", "");

                    // search for the next 'MSSK' header
                    var pattern = new byte[12] { 0x4b, 0x53, 0x53, 0x4d, 0x02, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00 };
                    var index = Helpers.ArrayIndexOf(decBlobBytes, pattern, offset);

                    if (index != -1)
                    {
                        offset = index;
                        offset += 20;

                        var aes256len = BitConverter.ToInt32(decBlobBytes, offset);
                        offset += 4;

                        if (aes256len != 32)
                        {
                            Console.WriteLine("    [X] Error parsing decrypted Policy.vpol (aes256len != 32)");
                            return keys;
                        }

                        var aes256Key = new byte[aes256len];
                        Array.Copy(decBlobBytes, offset, aes256Key, 0, aes256len);
                        var aes256KeyStr = BitConverter.ToString(aes256Key).Replace("-", "");

                        keys.Add(aes128Key);
                        keys.Add(aes256Key);
                    }
                    else
                    {
                        Console.WriteLine("[X] Error in decrypting Policy.vpol: second MSSK header not found!");
                    }
                }
            }

            return keys;
        }

        public static byte[] GetDomainKey(byte[] masterKeyBytes)
        {
            // helper to extract domain key bytes from a master key blob

            var offset = 96;

            var masterKeyLen = BitConverter.ToInt64(masterKeyBytes, offset);
            offset += 8;
            var backupKeyLen = BitConverter.ToInt64(masterKeyBytes, offset);
            offset += 8;
            var credHistLen = BitConverter.ToInt64(masterKeyBytes, offset);
            offset += 8;
            var domainKeyLen = BitConverter.ToInt64(masterKeyBytes, offset);
            offset += 8;

            offset += (int)(masterKeyLen + backupKeyLen + credHistLen);

            var domainKeyBytes = new byte[domainKeyLen];
            Array.Copy(masterKeyBytes, offset, domainKeyBytes, 0, domainKeyLen);

            return domainKeyBytes;
        }

        public static byte[] GetMasterKey(byte[] masterKeyBytes)
        {
            // helper to extract domain masterkey subbytes from a master key blob

            var offset = 96;

            var masterKeyLen = BitConverter.ToInt64(masterKeyBytes, offset);
            offset += 4 * 8; // skip the key length headers

            var masterKeySubBytes = new byte[masterKeyLen];
            Array.Copy(masterKeyBytes, offset, masterKeySubBytes, 0, masterKeyLen);

            return masterKeySubBytes;
        }
        
        public static byte[] CalculateKeys(string password, string directory, bool domain, string userSID = "")
        {
            var usersid = "";

            if (!String.IsNullOrEmpty(directory))
            {
                usersid = Path.GetFileName(directory).TrimEnd(Path.DirectorySeparatorChar);
            }
            else
            {
                usersid = userSID;
            }

            var utf16pass = Encoding.Unicode.GetBytes(password);
            var utf16sid = Encoding.Unicode.GetBytes(usersid);

            var utf16sidfinal = new byte[utf16sid.Length + 2];
            utf16sid.CopyTo(utf16sidfinal, 0);
            utf16sidfinal[utf16sidfinal.Length - 2] = 0x00;

            byte[] sha1bytes_password;
            byte[] hmacbytes;

            if (!domain)
            {
                //Calculate SHA1 from user password
                using (var sha1 = new SHA1CryptoServiceProvider())
                {
                    sha1bytes_password = sha1.ComputeHash(utf16pass);
                }
                var combined = Helpers.Combine(sha1bytes_password, utf16sidfinal);
                using (var hmac = new HMACSHA1(sha1bytes_password))
                {
                    hmacbytes = hmac.ComputeHash(utf16sidfinal);
                }
                return hmacbytes;
            }
            else
            {
                //Calculate NTLM from user password. Kerberos's RC4_HMAC key is the NTLM hash
                //Skip NTLM hashing if the password is in NTLM format
                string rc4Hash = Regex.IsMatch(password, "^[a-f0-9]{32}$", RegexOptions.IgnoreCase) ? password : 
                    Crypto.KerberosPasswordHash(Interop.KERB_ETYPE.rc4_hmac, password);

                var ntlm = Helpers.ConvertHexStringToByteArray(rc4Hash);

                var combinedNTLM = Helpers.Combine(ntlm, utf16sidfinal);
                byte[] ntlmhmacbytes;

                //Calculate SHA1 of NTLM from user password
                using (var hmac = new HMACSHA1(ntlm))
                {
                    ntlmhmacbytes = hmac.ComputeHash(utf16sidfinal);
                }

                byte[] tmpbytes1;
                byte[] tmpbytes2;
                byte[] tmpkey3bytes;

                using (var hMACSHA256 = new HMACSHA256())
                {
                    var deriveBytes = new Pbkdf2(hMACSHA256, ntlm, utf16sid, 10000);
                    tmpbytes1 = deriveBytes.GetBytes(32, "sha256");
                }

                using (var hMACSHA256 = new HMACSHA256())
                {
                    var deriveBytes = new Pbkdf2(hMACSHA256, tmpbytes1, utf16sid, 1);
                    tmpbytes2 = deriveBytes.GetBytes(16, "sha256");
                }

                using (var hmac = new HMACSHA1(tmpbytes2))
                {
                    tmpkey3bytes = hmac.ComputeHash(utf16sidfinal);
                }
                return tmpkey3bytes;
            }
        }

        public static KeyValuePair<string, string> DecryptMasterKey(byte[] masterKeyBytes, byte[] backupKeyBytes)
        {
            // takes masterkey bytes and backup key bytes, returns a dictionary of guid:sha1 masterkey mappings

            var guidMasterKey = $"{{{Encoding.Unicode.GetString(masterKeyBytes, 12, 72)}}}";

            var offset = 4;

            var domainKeyBytes = GetDomainKey(masterKeyBytes);

            var secretLen = BitConverter.ToInt32(domainKeyBytes, offset);
            offset += 4;

            var accesscheckLen = BitConverter.ToInt32(domainKeyBytes, offset);
            offset += 4;

            // the guid
            offset += 16;

            var secretBytes = new byte[secretLen];
            Array.Copy(domainKeyBytes, offset, secretBytes, 0, secretLen);
            offset += secretLen;

            var accesscheckBytes = new byte[accesscheckLen];
            Array.Copy(domainKeyBytes, offset, accesscheckBytes, 0, accesscheckLen);

            // extract out the RSA private key
            var rsaPriv = new byte[backupKeyBytes.Length - 24];
            Array.Copy(backupKeyBytes, 24, rsaPriv, 0, rsaPriv.Length);

            var a = BitConverter.ToString(rsaPriv).Replace("-", "");

            var sec = BitConverter.ToString(secretBytes).Replace("-", "");

            var domainKeyBytesDec = Crypto.RSADecrypt(rsaPriv, secretBytes);

            var masterKeyLen = BitConverter.ToInt32(domainKeyBytesDec, 0);
            var suppKeyLen = BitConverter.ToInt32(domainKeyBytesDec, 4);

            var masterKey = new byte[masterKeyLen];
            Buffer.BlockCopy(domainKeyBytesDec, 8, masterKey, 0, masterKeyLen);

            var sha1 = new SHA1CryptoServiceProvider();
            var masterKeySha1 = sha1.ComputeHash(masterKey);
            var masterKeySha1Hex = BitConverter.ToString(masterKeySha1).Replace("-", "");

            return new KeyValuePair<string, string>(guidMasterKey, masterKeySha1Hex);
        }

        public static KeyValuePair<string, string> DecryptMasterKeyWithSha(byte[] masterKeyBytes, byte[] shaBytes)
        {
            // takes masterkey bytes and SYSTEM_DPAPI masterkey sha bytes, returns a dictionary of guid:sha1 masterkey mappings
            var guidMasterKey = $"{{{Encoding.Unicode.GetString(masterKeyBytes, 12, 72)}}}";

            var mkBytes = GetMasterKey(masterKeyBytes);

            var offset = 4;
            var salt = new byte[16];
            Array.Copy(mkBytes, 4, salt, 0, 16);
            offset += 16;

            var rounds = BitConverter.ToInt32(mkBytes, offset);
            offset += 4;

            var algHash = BitConverter.ToInt32(mkBytes, offset);
            offset += 4;

            var algCrypt = BitConverter.ToInt32(mkBytes, offset);
            offset += 4;

            var encData = new byte[mkBytes.Length - offset];
            Array.Copy(mkBytes, offset, encData, 0, encData.Length);

            var derivedPreKey = DerivePreKey(shaBytes, algHash, salt, rounds);

            switch (algCrypt)
            {
                // CALG_AES_256 == 26128 , CALG_SHA_512 == 32782
                case 26128 when (algHash == 32782):
                    {
                        var masterKeySha1 = DecryptAes256HmacSha512(shaBytes, derivedPreKey, encData);
                        var masterKeyStr = BitConverter.ToString(masterKeySha1).Replace("-", "");

                        return new KeyValuePair<string, string>(guidMasterKey, masterKeyStr);
                    }

                // Support for 32777(CALG_HMAC) / 26115(CALG_3DES)
                case 26115 when (algHash == 32777 || algHash == 32772):
                    {
                        var masterKeySha1 = DecryptTripleDESHmac(shaBytes, derivedPreKey, encData);
                        var masterKeyStr = BitConverter.ToString(masterKeySha1).Replace("-", "");

                        return new KeyValuePair<string, string>(guidMasterKey, masterKeyStr);
                    }

                default:
                    throw new Exception($"Alg crypt '{algCrypt} / 0x{algCrypt:X8}' not currently supported!");
            }

        }

        private static byte[] DerivePreKey(byte[] shaBytes, int algHash, byte[] salt, int rounds)
        {
            byte[] derivedPreKey;

            switch (algHash)
            {
                // CALG_SHA_512 == 32782
                case 32782:
                    {
                        // derive the "Pbkdf2/SHA512" key for the masterkey, using MS' silliness
                        using (var hmac = new HMACSHA512())
                        {
                            var df = new Pbkdf2(hmac, shaBytes, salt, rounds);
                            derivedPreKey = df.GetBytes(48);
                        }

                        break;
                    }

                case 32777:
                    {
                        // derive the "Pbkdf2/SHA1" key for the masterkey, using MS' silliness
                        using (var hmac = new HMACSHA1())
                        {
                            var df = new Pbkdf2(hmac, shaBytes, salt, rounds);
                            derivedPreKey = df.GetBytes(32);
                        }

                        break;
                    }

                default:
                    throw new Exception($"alg hash  '{algHash} / 0x{algHash:X8}' not currently supported!");
            }

            return derivedPreKey;
        }

        private static byte[] DecryptAes256HmacSha512(byte[] shaBytes, byte[] final, byte[] encData)
        {
            var aesCryptoProvider = new AesCryptoServiceProvider();

            var ivBytes = new byte[16];
            Array.Copy(final, 32, ivBytes, 0, 16);

            var key = new byte[32];
            Array.Copy(final, 0, key, 0, 32);

            aesCryptoProvider.Key = key;
            aesCryptoProvider.IV = ivBytes;
            aesCryptoProvider.Mode = CipherMode.CBC;
            aesCryptoProvider.Padding = PaddingMode.Zeros;

            // decrypt the encrypted data using the Pbkdf2-derived key
            var plaintextBytes = aesCryptoProvider.CreateDecryptor().TransformFinalBlock(encData, 0, encData.Length);
            var masterKeyFull = new byte[64];
            Array.Copy(plaintextBytes, plaintextBytes.Length - masterKeyFull.Length, masterKeyFull, 0, masterKeyFull.Length);

            using (var sha1 = new SHA1CryptoServiceProvider())
            {
                var masterKeySha1 = sha1.ComputeHash(masterKeyFull);

                if (!IsValidHMAC(plaintextBytes, masterKeyFull, shaBytes, typeof(HMACSHA512)))
                    throw new Exception("HMAC integrity check failed!");

                return masterKeySha1;
            }
        }

        private static byte[] DecryptTripleDESHmac(byte[] shaBytes, byte[] final, byte[] encData)
        {
            var desCryptoProvider = new TripleDESCryptoServiceProvider();

            var ivBytes = new byte[8];
            var key = new byte[24];

            Array.Copy(final, 24, ivBytes, 0, 8);
            Array.Copy(final, 0, key, 0, 24);

            desCryptoProvider.Key = key;
            desCryptoProvider.IV = ivBytes;
            desCryptoProvider.Mode = CipherMode.CBC;
            desCryptoProvider.Padding = PaddingMode.Zeros;

            var plaintextBytes = desCryptoProvider.CreateDecryptor().TransformFinalBlock(encData, 0, encData.Length);
            var masterKeyFull = new byte[64];
            Array.Copy(plaintextBytes, plaintextBytes.Length - masterKeyFull.Length, masterKeyFull, 0, masterKeyFull.Length);

            using (var sha1 = new SHA1CryptoServiceProvider())
            {
                var masterKeySha1 = sha1.ComputeHash(masterKeyFull);

                if (!IsValidHMAC(plaintextBytes, masterKeyFull, shaBytes, typeof(HMACSHA1)))
                    throw new Exception("HMAC integrity check failed!");

                return masterKeySha1;
            }
        }

        private static bool IsValidHMAC(byte[] plaintextBytes, byte[] masterKeyFull, byte[] shaBytes, Type HMACType)
        {
            var obj = (HMAC)Activator.CreateInstance(HMACType);
            var HMACLen = obj.HashSize / 8;

            // we're HMAC'ing the first 16 bytes of the decrypted buffer with the shaBytes as the key
            var hmacSalt = new byte[16];
            Array.Copy(plaintextBytes, hmacSalt, 16);

            var hmac = new byte[HMACLen];
            Array.Copy(plaintextBytes, 16, hmac, 0, hmac.Length);

            var hmac1 = (HMAC)Activator.CreateInstance(HMACType, shaBytes);
            var round1Hmac = hmac1.ComputeHash(hmacSalt);

            // round 2
            var hmac2 = (HMAC)Activator.CreateInstance(HMACType, round1Hmac);
            var round2Hmac = hmac2.ComputeHash(masterKeyFull);

            // compare the second HMAC value to the original plaintextBytes, starting at index 16
            if (hmac.SequenceEqual(round2Hmac))
            {
                return true;
            }
            return false;
        }

        public static KeyValuePair<string, string> FormatHash(byte[] masterKeyBytes, string sid, int context = 3)
        {
            if (string.IsNullOrEmpty(sid) || masterKeyBytes == null)
                return default;

            var mkBytes = GetMasterKey(masterKeyBytes);
            var guidMasterKey = $"{{{Encoding.Unicode.GetString(masterKeyBytes, 12, 72)}}}";

            var offset = 4;
            var salt = new byte[16];
            Array.Copy(mkBytes, 4, salt, 0, 16);
            offset += 16;

            var rounds = BitConverter.ToInt32(mkBytes, offset);
            offset += 4;

            var algHash = BitConverter.ToInt32(mkBytes, offset);
            offset += 4;

            var algCrypt = BitConverter.ToInt32(mkBytes, offset);
            offset += 4;

            var encData = new byte[mkBytes.Length - offset];
            Array.Copy(mkBytes, offset, encData, 0, encData.Length);

            int version = 0;
            string cipherAlgo;
            string hmacAlgo;

            switch (algCrypt)
            {
                case 26128 when (algHash == 32782 || algHash == 32772):
                    version = 2;
                    cipherAlgo = "aes256";
                    hmacAlgo = "sha512";
                    break;
                case 26115 when (algHash == 32777):
                    version = 1;
                    cipherAlgo = "des3";
                    hmacAlgo = "sha1";
                    break;
                default:
                    throw new Exception($"Alg crypt '{algCrypt} / 0x{algCrypt:X8}' not currently supported!");
            }

            string hash = string.Format(
                "$DPAPImk${0}*{1}*{2}*{3}*{4}*{5}*{6}*{7}*{8}",
                version,
                context,
                sid,
                cipherAlgo,
                hmacAlgo,
                rounds,
                Helpers.ByteArrayToString(salt),
                encData.Length * 2,
                Helpers.ByteArrayToString(encData));

            return new KeyValuePair<string, string>(guidMasterKey, hash);
        }

        public static string GetPreferredKey(string file)
        {
            byte[] guidBytes = new byte[16];
            using (BinaryReader reader = new BinaryReader(new FileStream(file, FileMode.Open)))
            {
                reader.Read(guidBytes, 0, 16);
            }
            return new Guid(guidBytes).ToString();
        }

        public static string GetSidFromBKFile(string bkFile)
        {
            string sid = string.Empty;
            byte[] bkBytes = File.ReadAllBytes(bkFile);

            if (bkBytes.Length > 28)
            {
                try
                {
                    SecurityIdentifier sidObj = new SecurityIdentifier(bkBytes, 0x3c);
                    sid = sidObj.Value;
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[X] Failed to parse BK file: {ex.Message}");
                }
            }
            return sid;
        }

        public static string ExtractSidFromPath(string masterKeyPath)
        {
            string sid = String.Empty;

            // First check if there is a BK file we can get the SID from
            foreach (string file in Directory.GetFiles(Path.GetDirectoryName(masterKeyPath), "*", SearchOption.TopDirectoryOnly))
            {
                if (Path.GetFileName(file).StartsWith("BK-"))
                {
                    sid = GetSidFromBKFile(file);
                    if (!String.IsNullOrEmpty(sid))
                    {
                        //Console.WriteLine($"[*] Found SID from BK file: {sid}");
                        break;
                    }
                }
            }

            // Fall back to directory name
            if (String.IsNullOrEmpty(sid) && Regex.IsMatch(Path.GetDirectoryName(masterKeyPath),
                @"S-\d-\d+-(\d+-){1,14}\d+$", RegexOptions.IgnoreCase))
            {
                sid = Path.GetFileName(Path.GetDirectoryName(masterKeyPath));
                //Console.WriteLine($"[*] Found SID from path: {sid}");
            }
            return sid;
        }
    }
}