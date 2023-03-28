using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace SharpDPAPI
{
    /// <summary>
    /// Inspired by vletoux and gentilkiwi
    /// https://github.com/vletoux/MakeMeEnterpriseAdmin/blob/master/MakeMeEnterpriseAdmin.ps1
    /// Mimikatz: kull_m_rpc_ms-bkrp_c.c
    /// </summary>
    public class Bkrp
    {
        #region pinvoke
        [DllImport("Rpcrt4.dll", EntryPoint = "RpcBindingFromStringBindingW",
        CallingConvention = CallingConvention.StdCall,
        CharSet = CharSet.Unicode, SetLastError = false)]
        private static extern Int32 RpcBindingFromStringBinding(String bindingString, out IntPtr lpBinding);

        [DllImport("Rpcrt4.dll", EntryPoint = "NdrClientCall2", CallingConvention = CallingConvention.Cdecl,
           CharSet = CharSet.Unicode, SetLastError = false)]
        private static extern IntPtr NdrClientCall2(IntPtr pMIDL_STUB_DESC, IntPtr formatString, IntPtr h, IntPtr pguidActionAgent, IntPtr pDataIn, UInt32 cbDataIn, out IntPtr ppDataOut, out IntPtr pcbDataOut, UInt32 dwParam);

        [DllImport("Rpcrt4.dll", EntryPoint = "RpcBindingFree", CallingConvention = CallingConvention.StdCall,
            CharSet = CharSet.Unicode, SetLastError = false)]
        private static extern Int32 RpcBindingFree(ref IntPtr lpString);

        //#region RpcStringBindingCompose

        [DllImport("Rpcrt4.dll", EntryPoint = "RpcStringBindingComposeW", CallingConvention = CallingConvention.StdCall,
            CharSet = CharSet.Unicode, SetLastError = false)]
        private static extern Int32 RpcStringBindingCompose(
            String ObjUuid, String ProtSeq, String NetworkAddr, String Endpoint, String Options,
            out IntPtr lpBindingString
            );

        [StructLayout(LayoutKind.Sequential)]
        private struct RPC_SECURITY_QOS
        {
            public Int32 Version;
            public Int32 Capabilities;
            public Int32 IdentityTracking;
            public Int32 ImpersonationType;
        };

        [DllImport("Rpcrt4.dll", EntryPoint = "RpcBindingSetAuthInfoExW", CallingConvention = CallingConvention.StdCall,
            CharSet = CharSet.Unicode, SetLastError = false)]
        private static extern Int32 RpcBindingSetAuthInfoEx(IntPtr lpBinding, string ServerPrincName,
                                           UInt32 AuthnLevel, UInt32 AuthnSvc, IntPtr identity, UInt32 AuthzSvc, ref RPC_SECURITY_QOS SecurityQOS);

        [DllImport("Rpcrt4.dll", EntryPoint = "RpcBindingSetOption", CallingConvention = CallingConvention.StdCall, SetLastError = false)]
        private static extern Int32 RpcBindingSetOption(IntPtr Binding, UInt32 Option, IntPtr OptionValue);

        [DllImport("Rpcrt4.dll", EntryPoint = "I_RpcBindingInqSecurityContext", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern Int32 I_RpcBindingInqSecurityContext(IntPtr Binding, out IntPtr SecurityContextHandle);


        [StructLayout(LayoutKind.Sequential)]
        private struct SecPkgContext_SessionKey
        {
            public UInt32 SessionKeyLength;
            public IntPtr SessionKey;
        }

        [DllImport("secur32.Dll", CharSet = CharSet.Auto, SetLastError = false)]
        private static extern int QueryContextAttributes(IntPtr hContext,
                                                        uint ulAttribute,
                                                        ref SecPkgContext_SessionKey pContextAttributes);

        [StructLayout(LayoutKind.Sequential)]
        private struct CRYPTO_BUFFER
        {
            public UInt32 Length;
            public UInt32 MaximumLength;
            public IntPtr Buffer;
        }

        [DllImport("advapi32.Dll", CharSet = CharSet.Auto, SetLastError = false, EntryPoint = "SystemFunction032")]
        private static extern int SystemFunction032(ref CRYPTO_BUFFER data, ref CRYPTO_BUFFER key);

        [DllImport("advapi32.dll", SetLastError = true, EntryPoint = "SystemFunction027")]
        private static extern int RtlDecryptDES2blocks1DWORD(byte[] data, ref UInt32 key, IntPtr output);


        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern IntPtr GetSidSubAuthority(IntPtr sid, UInt32 subAuthorityIndex);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern IntPtr GetSidSubAuthorityCount(IntPtr psid);
        #endregion

        #region rpc initialization
        private byte[] MIDL_ProcFormatString;
        private byte[] MIDL_TypeFormatString;
        private GCHandle procString;
        private GCHandle formatString;
        private GCHandle stub;
        private GCHandle faultoffsets;
        private GCHandle clientinterface;

        public UInt32 RPCTimeOut = 1000;

        [StructLayout(LayoutKind.Sequential)]
        private struct COMM_FAULT_OFFSETS
        {
            public short CommOffset;
            public short FaultOffset;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct GENERIC_BINDING_ROUTINE_PAIR
        {
            public IntPtr Bind;
            public IntPtr Unbind;
        }


        [StructLayout(LayoutKind.Sequential)]
        private struct RPC_VERSION
        {
            public ushort MajorVersion;
            public ushort MinorVersion;

            public RPC_VERSION(ushort InterfaceVersionMajor, ushort InterfaceVersionMinor)
            {
                MajorVersion = InterfaceVersionMajor;
                MinorVersion = InterfaceVersionMinor;
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct RPC_SYNTAX_IDENTIFIER
        {
            public Guid SyntaxGUID;
            public RPC_VERSION SyntaxVersion;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct RPC_CLIENT_INTERFACE
        {
            public uint Length;
            public RPC_SYNTAX_IDENTIFIER InterfaceId;
            public RPC_SYNTAX_IDENTIFIER TransferSyntax;
            public IntPtr /*PRPC_DISPATCH_TABLE*/ DispatchTable;
            public uint RpcProtseqEndpointCount;
            public IntPtr /*PRPC_PROTSEQ_ENDPOINT*/ RpcProtseqEndpoint;
            public IntPtr Reserved;
            public IntPtr InterpreterInfo;
            public uint Flags;

            public static readonly Guid IID_SYNTAX = new Guid(0x8A885D04u, 0x1CEB, 0x11C9, 0x9F, 0xE8, 0x08, 0x00, 0x2B,
                                                              0x10,
                                                              0x48, 0x60);

            public RPC_CLIENT_INTERFACE(Guid iid, ushort InterfaceVersionMajor, ushort InterfaceVersionMinor)
            {
                Length = (uint)Marshal.SizeOf(typeof(RPC_CLIENT_INTERFACE));
                RPC_VERSION rpcVersion = new RPC_VERSION(InterfaceVersionMajor, InterfaceVersionMinor);
                InterfaceId = new RPC_SYNTAX_IDENTIFIER();
                InterfaceId.SyntaxGUID = iid;
                InterfaceId.SyntaxVersion = rpcVersion;
                rpcVersion = new RPC_VERSION(2, 0);
                TransferSyntax = new RPC_SYNTAX_IDENTIFIER();
                TransferSyntax.SyntaxGUID = IID_SYNTAX;
                TransferSyntax.SyntaxVersion = rpcVersion;
                DispatchTable = IntPtr.Zero;
                RpcProtseqEndpointCount = 0u;
                RpcProtseqEndpoint = IntPtr.Zero;
                Reserved = IntPtr.Zero;
                InterpreterInfo = IntPtr.Zero;
                Flags = 0u;
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MIDL_STUB_DESC
        {
            public IntPtr /*RPC_CLIENT_INTERFACE*/ RpcInterfaceInformation;
            public IntPtr pfnAllocate;
            public IntPtr pfnFree;
            public IntPtr pAutoBindHandle;
            public IntPtr /*NDR_RUNDOWN*/ apfnNdrRundownRoutines;
            public IntPtr /*GENERIC_BINDING_ROUTINE_PAIR*/ aGenericBindingRoutinePairs;
            public IntPtr /*EXPR_EVAL*/ apfnExprEval;
            public IntPtr /*XMIT_ROUTINE_QUINTUPLE*/ aXmitQuintuple;
            public IntPtr pFormatTypes;
            public int fCheckBounds;
            /* Ndr library version. */
            public uint Version;
            public IntPtr /*MALLOC_FREE_STRUCT*/ pMallocFreeStruct;
            public int MIDLVersion;
            public IntPtr CommFaultOffsets;
            // New fields for version 3.0+
            public IntPtr /*USER_MARSHAL_ROUTINE_QUADRUPLE*/ aUserMarshalQuadruple;
            // Notify routines - added for NT5, MIDL 5.0
            public IntPtr /*NDR_NOTIFY_ROUTINE*/ NotifyRoutineTable;
            public IntPtr mFlags;
            // International support routines - added for 64bit post NT5
            public IntPtr /*NDR_CS_ROUTINES*/ CsRoutineTables;
            public IntPtr ProxyServerInfo;
            public IntPtr /*NDR_EXPR_DESC*/ pExprInfo;
            // Fields up to now present in win2000 release.

            public MIDL_STUB_DESC(IntPtr pFormatTypesPtr, IntPtr RpcInterfaceInformationPtr,
                                    IntPtr pfnAllocatePtr, IntPtr pfnFreePtr, IntPtr aGenericBindingRoutinePairsPtr)
            {
                pFormatTypes = pFormatTypesPtr;
                RpcInterfaceInformation = RpcInterfaceInformationPtr;
                CommFaultOffsets = IntPtr.Zero;
                pfnAllocate = pfnAllocatePtr;
                pfnFree = pfnFreePtr;
                pAutoBindHandle = IntPtr.Zero;
                apfnNdrRundownRoutines = IntPtr.Zero;
                aGenericBindingRoutinePairs = aGenericBindingRoutinePairsPtr;
                apfnExprEval = IntPtr.Zero;
                aXmitQuintuple = IntPtr.Zero;
                fCheckBounds = 1;
                Version = 0x60000;
                pMallocFreeStruct = IntPtr.Zero;
                MIDLVersion = 0x8000253;
                aUserMarshalQuadruple = IntPtr.Zero;
                NotifyRoutineTable = IntPtr.Zero;
                mFlags = new IntPtr(0x00000001);
                CsRoutineTables = IntPtr.Zero;
                ProxyServerInfo = IntPtr.Zero;
                pExprInfo = IntPtr.Zero;
            }
        }

        private void InitializeStub(Guid interfaceID, byte[] MIDL_ProcFormatString, byte[] MIDL_TypeFormatString, ushort MajorVerson, ushort MinorVersion)
        {
            this.MIDL_ProcFormatString = MIDL_ProcFormatString;
            this.MIDL_TypeFormatString = MIDL_TypeFormatString;
            procString = GCHandle.Alloc(this.MIDL_ProcFormatString, GCHandleType.Pinned);

            RPC_CLIENT_INTERFACE clientinterfaceObject = new RPC_CLIENT_INTERFACE(interfaceID, MajorVerson, MinorVersion);

            COMM_FAULT_OFFSETS commFaultOffset = new COMM_FAULT_OFFSETS();
            commFaultOffset.CommOffset = -1;
            commFaultOffset.FaultOffset = -1;
            faultoffsets = GCHandle.Alloc(commFaultOffset, GCHandleType.Pinned);
            clientinterface = GCHandle.Alloc(clientinterfaceObject, GCHandleType.Pinned);
            formatString = GCHandle.Alloc(MIDL_TypeFormatString, GCHandleType.Pinned);

            MIDL_STUB_DESC stubObject = new MIDL_STUB_DESC(formatString.AddrOfPinnedObject(),
                                                            clientinterface.AddrOfPinnedObject(),
                                                            Marshal.GetFunctionPointerForDelegate((allocmemory)AllocateMemory),
                                                            Marshal.GetFunctionPointerForDelegate((freememory)FreeMemory),
                                                            IntPtr.Zero);

            stub = GCHandle.Alloc(stubObject, GCHandleType.Pinned);
        }

        private void freeStub()
        {
            procString.Free();
            faultoffsets.Free();
            clientinterface.Free();
            formatString.Free();
            stub.Free();
        }

        private static List<IntPtr> TrackedMemoryAllocations;

        delegate IntPtr allocmemory(int size);
        private static IntPtr AllocateMemory(int size)
        {
            IntPtr memory = Marshal.AllocHGlobal(size);
            if (TrackedMemoryAllocations != null)
            {
                TrackedMemoryAllocations.Add(memory);
            }
            return memory;
        }

        delegate void freememory(IntPtr memory);
        private static void FreeMemory(IntPtr memory)
        {
            Marshal.FreeHGlobal(memory);
            if (TrackedMemoryAllocations != null && TrackedMemoryAllocations.Contains(memory))
            {
                TrackedMemoryAllocations.Remove(memory);
            }
        }

        private static void EnableMemoryTracking()
        {
            TrackedMemoryAllocations = new List<IntPtr>();
        }

        private static void FreeTrackedMemoryAndRemoveTracking()
        {
            List<IntPtr> list = TrackedMemoryAllocations;
            TrackedMemoryAllocations = null;
            foreach (IntPtr memory in list)
            {
                Marshal.FreeHGlobal(memory);
            }
        }

        private IntPtr Bind(string server)
        {
            IntPtr bindingstring = IntPtr.Zero;
            IntPtr binding = IntPtr.Zero;
            Int32 status;

            status = RpcStringBindingCompose(null, "ncacn_np", server, @"\pipe\protected_storage", null, out bindingstring);
            if (status != 0)
                return IntPtr.Zero;
            status = RpcBindingFromStringBinding(Marshal.PtrToStringUni(bindingstring), out binding);
            RpcBindingFree(ref bindingstring);
            if (status != 0)
                return IntPtr.Zero;

            RPC_SECURITY_QOS qos = new RPC_SECURITY_QOS();
            qos.Version = 1;
            qos.Capabilities = 8;
            qos.ImpersonationType = 3;
            GCHandle qoshandle = GCHandle.Alloc(qos, GCHandleType.Pinned);

            status = RpcBindingSetAuthInfoEx(binding, "ProtectedStorage/" + server, 6, 9, IntPtr.Zero, 0, ref qos);
            qoshandle.Free();
            if (status != 0)
            {
                Unbind(binding);
                return IntPtr.Zero;
            }
            return binding;
        }

        private static void Unbind(IntPtr hBinding)
        {
            RpcBindingFree(ref hBinding);
        }

        private IntPtr GetProcStringHandle(int offset)
        {
            return Marshal.UnsafeAddrOfPinnedArrayElement(MIDL_ProcFormatStringBackuprKeyx64, offset);
        }

        private IntPtr GetStubHandle()
        {
            return stub.AddrOfPinnedObject();
        }
                #endregion

        #region MIDL strings
        private static byte[] MIDL_ProcFormatStringBackuprKeyx64 = new byte[] {
            0x00, 0x48, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x32, 0x00, 0x00, 0x00, 0x54, 0x00, 0x24, 0x00, 0x47, 0x07, 0x0a, 0x07, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x01,
            0x08, 0x00, 0x0c, 0x00, 0x0b, 0x01, 0x10, 0x00, 0x1c, 0x00, 0x48, 0x00, 0x18, 0x00, 0x08, 0x00, 0x13, 0x20, 0x20, 0x00, 0x28, 0x00, 0x50, 0x21, 0x28, 0x00, 0x08, 0x00, 0x48, 0x00, 0x30, 0x00,
            0x08, 0x00, 0x70, 0x00, 0x38, 0x00, 0x08, 0x00, 0x00 };
        private static byte[] MIDL_TypeFormatStringBackuprKeyx64 = new byte[] {
            0x00, 0x00, 0x11, 0x00, 0x08, 0x00, 0x1d, 0x00, 0x08, 0x00, 0x01, 0x5b, 0x15, 0x03, 0x10, 0x00, 0x08, 0x06, 0x06, 0x4c, 0x00, 0xf1, 0xff, 0x5b, 0x11, 0x00, 0x02, 0x00, 0x1b, 0x00, 0x01, 0x00,
            0x29, 0x00, 0x18, 0x00, 0x00, 0x00, 0x01, 0x5b, 0x11, 0x14, 0x02, 0x00, 0x12, 0x00, 0x02, 0x00, 0x1b, 0x00, 0x01, 0x00, 0x29, 0x54, 0x28, 0x00, 0x00, 0x00, 0x01, 0x5b, 0x11, 0x0c, 0x08, 0x5c,
            0x00 };
        private static byte[] MIDL_ProcFormatStringBackuprKeyx86 = new byte[] {
            0x00, 0x48, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x32, 0x00, 0x00, 0x00, 0x54, 0x00, 0x24, 0x00, 0x47, 0x07, 0x08, 0x07, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x01, 0x04, 0x00,
            0x0c, 0x00, 0x0b, 0x01, 0x08, 0x00, 0x1c, 0x00, 0x48, 0x00, 0x0c, 0x00, 0x08, 0x00, 0x13, 0x20, 0x10, 0x00, 0x28, 0x00, 0x50, 0x21, 0x14, 0x00, 0x08, 0x00, 0x48, 0x00, 0x18, 0x00, 0x08, 0x00,
            0x70, 0x00, 0x1c, 0x00, 0x08, 0x00, 0x00 };
        private static byte[] MIDL_TypeFormatStringBackuprKeyx86 = new byte[] {
            0x00, 0x00, 0x11, 0x00, 0x08, 0x00, 0x1d, 0x00, 0x08, 0x00, 0x01, 0x5b, 0x15, 0x03, 0x10, 0x00, 0x08, 0x06, 0x06, 0x4c, 0x00, 0xf1, 0xff, 0x5b, 0x11, 0x00, 0x02, 0x00, 0x1b, 0x00, 0x01, 0x00,
            0x29, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x01, 0x5b, 0x11, 0x14, 0x02, 0x00, 0x12, 0x00, 0x02, 0x00, 0x1b, 0x00, 0x01, 0x00, 0x29, 0x54, 0x14, 0x00, 0x00, 0x00, 0x01, 0x5b, 0x11, 0x0c, 0x08, 0x5c,
            0x00 };
        #endregion

        #region RPC structures
        [StructLayout(LayoutKind.Sequential)]
        private struct DRS_EXTENSIONS_INT
        {
            public UInt32 cb;
            public UInt32 dwFlags;
            public Guid SiteObjGuid;
            public UInt32 Pid;
            public UInt32 dwReplEpoch;
            public UInt32 dwFlagsExt;
            public Guid ConfigObjGUID;
            public UInt32 dwExtCaps;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct USN_VECTOR
        {
            public long usnHighObjUpdate;
            public long usnReserved;
            public long usnHighPropUpdate;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SCHEMA_PREFIX_TABLE
        {
            public UInt32 PrefixCount;
            public IntPtr pPrefixEntry;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ATTRVALBLOCK
        {
            public UInt32 valCount;
            public IntPtr pAVal;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ATTRBLOCK
        {
            public UInt32 attrCount;
            public IntPtr pAttr;
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct ENTINF
        {
            public IntPtr pName;
            public UInt32 ulFlags;
            public ATTRBLOCK AttrBlock;
        };
        #endregion

        #region Bkrp class and public interfaces
        private IntPtr hBind;
        private Guid BACKUPKEY_RESTORE_GUID = new Guid("47270C64-2FC7-499B-AC5B-0E37CDCE899A");
        private Guid MS_BKRP_INTERFACE_ID = new Guid("3DDE7C30-165D-11D1-AB8F-00805F14DB40");

        public Bkrp()
        {
            if (IntPtr.Size == 8)
            {
                InitializeStub(this.MS_BKRP_INTERFACE_ID, MIDL_ProcFormatStringBackuprKeyx64, MIDL_TypeFormatStringBackuprKeyx64, 1, 0);
            }
            else
            {
                InitializeStub(this.MS_BKRP_INTERFACE_ID, MIDL_ProcFormatStringBackuprKeyx86, MIDL_TypeFormatStringBackuprKeyx86, 1, 0);
            }
        }

        ~Bkrp()
        {
            Uninitialize();
        }

        public void Initialize(string server, string domain)
        {
            try
            {
                this.hBind = Bind(server);
                if (this.hBind == IntPtr.Zero)
                    throw new Exception("Unable to connect to the server " + server);
            }
            catch (Exception)
            {
                if (this.hBind != IntPtr.Zero)
                    Unbind(this.hBind);
                this.hBind = IntPtr.Zero;
            }
        }

        private void Uninitialize()
        {
            if (hBind != IntPtr.Zero)
                Unbind(hBind);
        }
        #endregion

        #region drsr rpc functions and decoding functions
        public byte[] BackuprKey(byte[] domainKeyBytes)
        {
            EnableMemoryTracking();

            IntPtr result = IntPtr.Zero;
            var stub = GetStubHandle();
            var handle = GetProcStringHandle(0);

            GCHandle guidHandle = GCHandle.Alloc(this.BACKUPKEY_RESTORE_GUID, GCHandleType.Pinned);
            IntPtr guidPtr = guidHandle.AddrOfPinnedObject();

            GCHandle domainKeyHandle = GCHandle.Alloc(domainKeyBytes, GCHandleType.Pinned);
            IntPtr domainKeyPtr = domainKeyHandle.AddrOfPinnedObject();

            IntPtr ppDataOut = IntPtr.Zero;
            IntPtr pcbDataOut = IntPtr.Zero;

            uint domainKeyLength = Convert.ToUInt32(domainKeyBytes.Length);
            uint dwParams = Convert.ToUInt32(0);

            try
            {
                result = NdrClientCall2(stub, handle, this.hBind, guidPtr, domainKeyPtr, domainKeyLength, out ppDataOut, out pcbDataOut, dwParams);
                byte[] managedArray = new byte[64];
                IntPtr ptr = new IntPtr(ppDataOut.ToInt64() + 4);
                Marshal.Copy(ptr, managedArray, 0, 64);
                return managedArray;
            }
            catch (Exception)
            {
                throw new Exception("Error decrypting masterkey via RPC");
            }
            finally
            {
                guidHandle.Free();
                domainKeyHandle.Free();
                this.freeStub();
                FreeTrackedMemoryAndRemoveTracking();
            }
        }
        #endregion
    }
}