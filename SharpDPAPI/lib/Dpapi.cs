using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace SharpDPAPI
{
    public class Dpapi
    {
        public static byte[] DescribeDPAPIBlob(byte[] blobBytes, Dictionary<string, string> MasterKeys, string blobType = "credential")
        {
            // parses a DPAPI credential or vault policy blob, also returning the decrypted blob plaintext

            // credentialBytes  ->  byte array of the credential file
            // MasterKeys       ->  dictionary of GUID:Sha1(MasterKey) mappings for decryption
            // blobType         ->  "credential" or vault "policy"

            int offset = 0;
            if (blobType.Equals("credential"))
            {
                offset = 36;
            }
            else if (blobType.Equals("policy"))
            {
                offset = 24;
            }
            else
            {
                Console.WriteLine("[X] Unsupported blob type: {0}", blobType);
                return new byte[0];
            }

            byte[] guidMasterKeyBytes = new byte[16];
            Array.Copy(blobBytes, offset, guidMasterKeyBytes, 0, 16);
            Guid guidMasterKey = new Guid(guidMasterKeyBytes);
            string guidString = String.Format("{{{0}}}", guidMasterKey);
            Console.WriteLine("    guidMasterKey    : {0}", guidString);
            offset += 16;

            Console.WriteLine("    size             : {0}", blobBytes.Length);

            UInt32 flags = BitConverter.ToUInt32(blobBytes, offset);
            offset += 4;
            Console.Write("    flags            : 0x{0}", flags.ToString("X"));
            if ((flags & 0x20000000) == flags)
            {
                Console.Write(" (CRYPTPROTECT_SYSTEM)");
            }
            Console.WriteLine();

            int descLength = BitConverter.ToInt32(blobBytes, offset);
            offset += 4;
            string description = Encoding.Unicode.GetString(blobBytes, offset, descLength);
            offset += descLength;

            int algCrypt = BitConverter.ToInt32(blobBytes, offset);
            offset += 4;

            int algCryptLen = BitConverter.ToInt32(blobBytes, offset);
            offset += 4;

            int saltLen = BitConverter.ToInt32(blobBytes, offset);
            offset += 4;

            byte[] saltBytes = new byte[saltLen];
            Array.Copy(blobBytes, offset, saltBytes, 0, saltLen);
            offset += saltLen;

            int hmacKeyLen = BitConverter.ToInt32(blobBytes, offset);
            offset += 4 + hmacKeyLen;

            int algHash = BitConverter.ToInt32(blobBytes, offset);
            offset += 4;

            Console.WriteLine("    algHash/algCrypt : {0}/{1}", algHash, algCrypt);

            Console.WriteLine("    description      : {0}", description);

            int algHashLen = BitConverter.ToInt32(blobBytes, offset);
            offset += 4;

            int hmac2KeyLen = BitConverter.ToInt32(blobBytes, offset);
            offset += 4 + hmac2KeyLen;

            int dataLen = BitConverter.ToInt32(blobBytes, offset);
            offset += 4;
            byte[] dataBytes = new byte[dataLen];
            Array.Copy(blobBytes, offset, dataBytes, 0, dataLen);

            if (MasterKeys.ContainsKey(guidString))
            {
                // if this key is present, decrypt this blob

                if (algHash == 32782)
                {
                    // grab the sha1(masterkey) from the cache
                    byte[] keyBytes = Helpers.StringToByteArray(MasterKeys[guidString].ToString());

                    // derive the session key
                    byte[] derivedKeyBytes = Crypto.DeriveKey(keyBytes, saltBytes, algHash);
                    byte[] finalKeyBytes = new byte[algCryptLen / 8];
                    Array.Copy(derivedKeyBytes, finalKeyBytes, algCryptLen / 8);

                    // decrypt the blob with the session key
                    return Crypto.DecryptBlob(dataBytes, finalKeyBytes, algCrypt);
                }
                else if (algHash == 32772)
                {
                    // grab the sha1(masterkey) from the cache
                    byte[] keyBytes = Helpers.StringToByteArray(MasterKeys[guidString].ToString());

                    // derive the session key
                    byte[] derivedKeyBytes = Crypto.DeriveKey(keyBytes, saltBytes, algHash);
                    byte[] finalKeyBytes = new byte[algCryptLen / 8];
                    Array.Copy(derivedKeyBytes, finalKeyBytes, algCryptLen / 8);

                    // decrypt the blob with the session key
                    return Crypto.DecryptBlob(dataBytes, finalKeyBytes, algCrypt);
                }
                else
                {
                    Console.WriteLine("    [X] Only sha1 and sha256 are currently supported for the hash algorithm. Alg '{0}' not supported", algHash);
                }
            }
            else
            {
                Console.WriteLine("    [X] MasterKey GUID not in cache: {0}", guidString);
            }
            Console.WriteLine();

            return new byte[0];
        }

        public static ArrayList DescribePolicy(byte[] policyBytes, Dictionary<string, string> MasterKeys)
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
            
            int offset = 0;

            int version = BitConverter.ToInt32(policyBytes, offset);
            offset += 4;

            byte[] vaultIDbytes = new byte[16];
            Array.Copy(policyBytes, offset, vaultIDbytes, 0, 16);
            Guid vaultID = new Guid(vaultIDbytes);
            offset += 16;

            Console.WriteLine("\r\n  VaultID            : {0}", vaultID);

            int nameLen = BitConverter.ToInt32(policyBytes, offset);
            offset += 4;
            string name = Encoding.Unicode.GetString(policyBytes, offset, nameLen);
            offset += nameLen;
            Console.WriteLine("  Name               : {0}", name);

            // skip unk0/unk1/unk2
            offset += 12;

            int keyLen = BitConverter.ToInt32(policyBytes, offset);
            offset += 4;

            // skip unk0/unk1 GUIDs
            offset += 32;

            int keyBlobLen = BitConverter.ToInt32(policyBytes, offset);
            offset += 4;

            // extract out the DPAPI blob
            byte[] blobBytes = new byte[keyBlobLen];
            Array.Copy(policyBytes, offset, blobBytes, 0, keyBlobLen);

            // 24 -> offset where the masterkey GUID starts
            byte[] plaintextBytes = DescribeDPAPIBlob(blobBytes, MasterKeys, "policy");

            if (plaintextBytes.Length > 0)
            {
                ArrayList keys = ParseDecPolicyBlob(plaintextBytes);

                string aes128KeyStr = BitConverter.ToString((byte[])keys[0]).Replace("-", "");
                Console.WriteLine("    aes128 key       : {0}", aes128KeyStr);

                string aes256KeyStr = BitConverter.ToString((byte[])keys[1]).Replace("-", "");
                Console.WriteLine("    aes256 key       : {0}", aes256KeyStr);

                return keys;
            }
            else
            {
                return new ArrayList();
            }
        }

        public static void DescribeVault(byte[] vaultBytes, ArrayList AESKeys)
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

            byte[] aes128key = (byte[])AESKeys[0];
            byte[] aes256key = (byte[])AESKeys[1];

            int offset = 0;

            // skip the schema GUID
            offset += 16;

            // skip unk0
            offset += 4;

            long lastWritten = (long)BitConverter.ToInt64(vaultBytes, offset);
            offset += 8;
            System.DateTime lastWrittenTime = System.DateTime.FromFileTime(lastWritten);
            Console.WriteLine("\r\n    LastWritten      : {0}", lastWrittenTime);

            // skip unk1/unk2
            offset += 8;

            int friendlyNameLen = BitConverter.ToInt32(vaultBytes, offset);
            offset += 4;

            string friendlyName = Encoding.Unicode.GetString(vaultBytes, offset, friendlyNameLen);
            offset += friendlyNameLen;
            Console.WriteLine("    FriendlyName     : {0}", friendlyName);

            int attributeMapLen = BitConverter.ToInt32(vaultBytes, offset);
            offset += 4;

            // https://github.com/gentilkiwi/mimikatz/blob/110a831ebe7b529c5dd3010f9e7fced0d3e3a46c/modules/kull_m_cred.h#L133-L137
            /*
                typedef struct _KULL_M_CRED_VAULT_CREDENTIAL_ATTRIBUTE_MAP {
	                DWORD id;
	                DWORD offset; //maybe 64
	                DWORD unk;
                } KULL_M_CRED_VAULT_CREDENTIAL_ATTRIBUTE_MAP
             */

            int numberOfAttributes = attributeMapLen / 12;

            Dictionary<int, int> attributeMap = new Dictionary<int, int>();

            for (int i = 0; i < numberOfAttributes; ++i)
            {
                int attributeNum = BitConverter.ToInt32(vaultBytes, offset);
                offset += 4;
                int attributeOffset = BitConverter.ToInt32(vaultBytes, offset);
                offset += 8; // skip unk

                attributeMap.Add(attributeNum, attributeOffset);
            }

            foreach (KeyValuePair<int, int> attribute in attributeMap)
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
                int attributeOffset = attribute.Value;

                // skip cruft
                attributeOffset += 16;

                if(attribute.Key >= 100)
                {
                    attributeOffset += 4; // id100 https://github.com/SecureAuthCorp/impacket/blob/13a65706273680c297caee0211460ef7369aa8ca/impacket/dpapi.py#L551-L552
                }

                int dataLen = BitConverter.ToInt32(vaultBytes, attributeOffset);
                attributeOffset += 4;

                if (dataLen > 0)
                {
                    bool IVPresent = BitConverter.ToBoolean(vaultBytes, attributeOffset);
                    attributeOffset += 1;

                    if (!IVPresent)
                    {
                        // we don't really care about these... do we?

                        /*
                        byte[] dataBytes = new byte[dataLen - 1];

                        // use aes128, no IV
                        Array.Copy(vaultBytes, attributeOffset, dataBytes, 0, dataLen-1);
                        string s = BitConverter.ToString(dataBytes).Replace("-", "");
                        
                        byte[] decBytes = Crypto.AESDecrypt(aes128key, new byte[0], dataBytes);
                        string dec = BitConverter.ToString(decBytes).Replace("-", "");
                        */
                    }
                    else
                    {
                        // use aes256 w/ IV

                        int IVLen = BitConverter.ToInt32(vaultBytes, attributeOffset);
                        attributeOffset += 4;
                        
                        byte[] IVBytes = new byte[IVLen];
                        Array.Copy(vaultBytes, attributeOffset, IVBytes, 0, IVLen);
                        attributeOffset += IVLen;

                        byte[] dataBytes = new byte[dataLen - 1 - 4 - IVLen];
                        Array.Copy(vaultBytes, attributeOffset, dataBytes, 0, dataLen - 1 - 4 - IVLen);

                        byte[] decBytes = Crypto.AESDecrypt(aes256key, IVBytes, dataBytes);
                        string dec = BitConverter.ToString(decBytes).Replace("-", "");

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

            int offset = 0;

            int version = BitConverter.ToInt32(vaultItemBytes, offset);
            offset += 4;

            int count = BitConverter.ToInt32(vaultItemBytes, offset);
            offset += 4;

            // skip unk
            offset += 4;

            for(int i = 0; i < count; ++i)
            {
                int id = BitConverter.ToInt32(vaultItemBytes, offset);
                offset += 4;

                int size = BitConverter.ToInt32(vaultItemBytes, offset);
                offset += 4;

                string entryString = Encoding.Unicode.GetString(vaultItemBytes, offset, size);

                byte[] entryData = new byte[size];
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
                        string entryDataString = BitConverter.ToString(entryData).Replace("-", " ");
                        //Console.WriteLine("    Property         : {0}", entryDataString);
                        break;
                }
            }
        }

        public static void DescribeCredential(byte[] credentialBytes, Dictionary<string, string> MasterKeys)
        {
            // try to decrypt the credential blob, displaying if successful
            byte[] plaintextBytes = DescribeDPAPIBlob(credentialBytes, MasterKeys, "credential");
            if (plaintextBytes.Length > 0)
            {
                ParseDecCredBlob(plaintextBytes);
            }
        }

        public static void ParseDecCredBlob(byte[] decBlobBytes)
        {
            // parse/display a decrypted credential blob

            int offset = 0;

            UInt32 credFlags = BitConverter.ToUInt32(decBlobBytes, offset);
            offset += 4;
            UInt32 credSize = BitConverter.ToUInt32(decBlobBytes, offset);
            offset += 4;
            UInt32 credUnk0 = BitConverter.ToUInt32(decBlobBytes, offset);
            offset += 4;
            UInt32 type = BitConverter.ToUInt32(decBlobBytes, offset);
            offset += 4;
            UInt32 flags = BitConverter.ToUInt32(decBlobBytes, offset);
            offset += 4;

            long lastWritten = (long)BitConverter.ToInt64(decBlobBytes, offset);
            offset += 8;
            System.DateTime lastWrittenTime = System.DateTime.FromFileTime(lastWritten);
            Console.WriteLine("    LastWritten      : {0}", lastWrittenTime);

            UInt32 unkFlagsOrSize = BitConverter.ToUInt32(decBlobBytes, offset);
            offset += 4;
            UInt32 persist = BitConverter.ToUInt32(decBlobBytes, offset);
            offset += 4;
            UInt32 attributeCount = BitConverter.ToUInt32(decBlobBytes, offset);
            offset += 4;
            UInt32 unk0 = BitConverter.ToUInt32(decBlobBytes, offset);
            offset += 4;
            UInt32 unk1 = BitConverter.ToUInt32(decBlobBytes, offset);
            offset += 4;

            Int32 targetNameLen = BitConverter.ToInt32(decBlobBytes, offset);
            offset += 4;
            string targetName = Encoding.Unicode.GetString(decBlobBytes, offset, targetNameLen);
            offset += targetNameLen;
            Console.WriteLine("    TargetName       : {0}", targetName);

            Int32 targetAliasLen = BitConverter.ToInt32(decBlobBytes, offset);
            offset += 4;
            string targetAlias = Encoding.Unicode.GetString(decBlobBytes, offset, targetAliasLen);
            offset += targetAliasLen;
            Console.WriteLine("    TargetAlias      : {0}", targetAlias);

            Int32 commentLen = BitConverter.ToInt32(decBlobBytes, offset);
            offset += 4;
            string comment = Encoding.Unicode.GetString(decBlobBytes, offset, commentLen);
            offset += commentLen;
            Console.WriteLine("    Comment          : {0}", comment);

            Int32 unkDataLen = BitConverter.ToInt32(decBlobBytes, offset);
            offset += 4;
            string unkData = Encoding.Unicode.GetString(decBlobBytes, offset, unkDataLen);
            offset += unkDataLen;

            Int32 userNameLen = BitConverter.ToInt32(decBlobBytes, offset);
            offset += 4;
            string userName = Encoding.Unicode.GetString(decBlobBytes, offset, userNameLen);
            offset += userNameLen;
            Console.WriteLine("    UserName         : {0}", userName);

            Int32 credBlobLen = BitConverter.ToInt32(decBlobBytes, offset);
            offset += 4;
            string credBlob = Encoding.Unicode.GetString(decBlobBytes, offset, credBlobLen);
            offset += credBlobLen;
            Console.WriteLine("    Credential       : {0}", credBlob);
        }

        public static ArrayList ParseDecPolicyBlob(byte[] decBlobBytes)
        {
            // parse a decrypted policy blob, returning an arraylist of the AES 128/256 keys

            int offset = 20;

            int aes128len = BitConverter.ToInt32(decBlobBytes, offset);
            offset += 4;

            byte[] aes128Key = new byte[aes128len];
            Array.Copy(decBlobBytes, offset, aes128Key, 0, aes128len);
            offset += aes128len;
            string aes128KeyStr = BitConverter.ToString(aes128Key).Replace("-", "");
            
            // skip more header stuff
            offset += 20;

            int aes256len = BitConverter.ToInt32(decBlobBytes, offset);
            offset += 4;

            byte[] aes256Key = new byte[aes256len];
            Array.Copy(decBlobBytes, offset, aes256Key, 0, aes256len);
            string aes256KeyStr = BitConverter.ToString(aes256Key).Replace("-", "");
            
            ArrayList keys = new ArrayList();

            keys.Add(aes128Key);
            keys.Add(aes256Key);

            return keys;
        }

        public static byte[] GetDomainKey(byte[] masterKeyBytes)
        {
            // helper to extract domain key bytes from a master key blob

            int offset = 96;

            long masterKeyLen = BitConverter.ToInt64(masterKeyBytes, offset);
            offset += 8;
            long backupKeyLen = BitConverter.ToInt64(masterKeyBytes, offset);
            offset += 8;
            long credHistLen = BitConverter.ToInt64(masterKeyBytes, offset);
            offset += 8;
            long domainKeyLen = BitConverter.ToInt64(masterKeyBytes, offset);
            offset += 8;

            offset += (int)(masterKeyLen + backupKeyLen + credHistLen);

            byte[] domainKeyBytes = new byte[domainKeyLen];
            Array.Copy(masterKeyBytes, offset, domainKeyBytes, 0, domainKeyLen);

            return domainKeyBytes;
        }

        public static Dictionary<string, string> DecryptMasterKey(byte[] masterKeyBytes, byte[] backupKeyBytes)
        {
            // takes masterkey bytes and backup key bytes, returns a dictionary of guid:sha1 masterkey mappings

            Dictionary<string, string> mapping = new Dictionary<string, string>();
            try
            {
                string guidMasterKey = String.Format("{{{0}}}", Encoding.Unicode.GetString(masterKeyBytes, 12, 72));

                int offset = 4;

                string bkb = BitConverter.ToString(backupKeyBytes).Replace("-", "");

                byte[] domainKeyBytes = GetDomainKey(masterKeyBytes);

                int secretLen = BitConverter.ToInt32(domainKeyBytes, offset);
                offset += 4;

                int accesscheckLen = BitConverter.ToInt32(domainKeyBytes, offset);
                offset += 4;

                // the guid
                offset += 16;

                byte[] secretBytes = new byte[secretLen];
                Array.Copy(domainKeyBytes, offset, secretBytes, 0, secretLen);
                offset += secretLen;

                byte[] accesscheckBytes = new byte[accesscheckLen];
                Array.Copy(domainKeyBytes, offset, accesscheckBytes, 0, accesscheckLen);

                // extract out the RSA private key
                byte[] rsaPriv = new byte[backupKeyBytes.Length - 24];
                Array.Copy(backupKeyBytes, 24, rsaPriv, 0, rsaPriv.Length);

                string a = BitConverter.ToString(rsaPriv).Replace("-", "");

                string sec = BitConverter.ToString(secretBytes).Replace("-", "");

                byte[] domainKeyBytesDec = Crypto.RSADecrypt(rsaPriv, secretBytes);

                int masteyKeyLen = BitConverter.ToInt32(domainKeyBytesDec, 0);
                int suppKeyLen = BitConverter.ToInt32(domainKeyBytesDec, 4);

                byte[] masterKey = new byte[masteyKeyLen];
                Buffer.BlockCopy(domainKeyBytesDec, 8, masterKey, 0, masteyKeyLen);

                SHA1Managed sha1 = new SHA1Managed();
                byte[] masterKeySha1 = sha1.ComputeHash(masterKey);
                string masterKeySha1Hex = BitConverter.ToString(masterKeySha1).Replace("-", "");

                mapping.Add(guidMasterKey, masterKeySha1Hex);
            }
            catch { }
            return mapping;
        }
    }
}