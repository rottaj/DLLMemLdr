#ifndef DLLMEMLDR_LIBRARY_H
#define DLLMEMLDR_LIBRARY_H

#include <windows.h>
#include <winternl.h>

#define GET_HEADER_DICTIONARY(module, idx)  &(module)->headers->OptionalHeader.DataDirectory[idx]
#define HOST_MACHINE IMAGE_FILE_MACHINE_AMD64
#define _LDR_MEMCPY_(dest, src, size) (memcpy((dest), (src), (size)))
#define _LDR_MEMSET_(dest, c, size) (memset((dest), (c), (size)))

#define LDR_ALLOCATE_VIRTUAL_MEMORY(hProcess, lpBuffer, dwSizeVirtual, lpAttributes, uProtect) \
    (API->VirtualAlloc((hProcess), (lpBuffer), 0, (dwSizeVirtual), (lpAttributes), (uProtect)))

#define LDR_PROTECT_VIRTUAL_MEMORY(hProcess, lpBuffer, dwSizeVirtual, access, puOldAccessRights) \
    (API->VirtualProtect((hProcess), (lpBuffer), (dwSizeVirtual), (access), (puOldAccessRights)))

#define LDR_FREE_VIRTUAL_MEMORY(hProcess, lpBuffer, dwSizeVirtual, dwFreeType) \
    (API->VirtualFree((hProcess), (lpBuffer), (dwSizeVirtual), (dwFreeType)))


typedef struct {
    PIMAGE_NT_HEADERS         headers;
    unsigned char            *codeBase;
    HMODULE                  *modules;
    INT                       numModules;
    DWORD                       pageSize;

} *PLDRINSTANCE, LDRINSTANCE;

HMODULE LdrGetModuleHandleC(IN LPCWSTR szModuleName);

PVOID LdrGetProcAddressC(IN HMODULE hModule, IN LPCWSTR lpProcName);

BOOL MemLdrEx(HANDLE hProcess, PVOID pPE);
BOOL MemLdr(PVOID pPE);

typedef NTSTATUS (NTAPI* fnLdrNtAllocateVirtualMemory)(
    IN          HANDLE      ProcessHandle,
    IN OUT      PVOID       BaseAddress,
    IN          ULONG       ZeroBits,
    IN OUT      PSIZE_T     RegionSize,
    IN          ULONG       AllocationType,
    IN          ULONG       Protect);

typedef NTSTATUS (NTAPI* fnLdrNtProtectVirtualMemory)(
    IN          HANDLE      ProcessHandle,
    IN OUT      PVOID       BaseAddress,
    IN OUT      PSIZE_T     NumberOfBytesToProtect,
    IN          ULONG       NewAccessProtection,
    OUT         PULONG      OldAccessProtection);

typedef NTSTATUS (NTAPI* fnLdrNtFreeVirtualMemory) (
    IN          HANDLE      ProcessHandle,
    IN          PVOID       BaseAddress,
    IN OUT      PULONG      RegionSize,
    IN          ULONG       FreeType);

typedef NTSTATUS (NTAPI* fnLdrNtLoadLibrary) (
    IN         PUNICODE_STRING DriverServiceName);

typedef struct {
    fnLdrNtAllocateVirtualMemory   VirtualAlloc;
    fnLdrNtProtectVirtualMemory    VirtualProtect;
    fnLdrNtFreeVirtualMemory       VirtualFree;
} *PLDR_API, LDR_API ;

typedef struct LDR_TEB_A
{
    struct _NT_TIB NtTib;                                                   //0x0
    VOID* EnvironmentPointer;                                               //0x1cG
    struct _CLIENT_ID ClientId;                                             //0x20
    VOID* ActiveRpcHandle;                                                  //0x28
    VOID* ThreadLocalStoragePointer;                                        //0x2c
    struct _PEB* ProcessEnvironmentBlock;                                   //0x30
    ULONG LastErrorValue;                                                   //0x34
    ULONG CountOfOwnedCriticalSections;                                     //0x38
    VOID* CsrClientThread;                                                  //0x3c
    VOID* Win32ThreadInfo;                                                  //0x40gg
    ULONG User32Reserved[26];                                               //0x44
    ULONG UserReserved[5];                                                  //0xac
    VOID* WOW32Reserved;                                                    //0xc0
    ULONG CurrentLocale;                                                    //0xc4
    ULONG FpSoftwareStatusRegister;                                         //0xc8
    VOID* SystemReserved1[54];                                              //0xcc
    LONG ExceptionCode;                                                     //0x1a4
    struct _ACTIVATION_CONTEXT_STACK* ActivationContextStackPointer;        //0x1a8
    UCHAR SpareBytes[36];                                                   //0x1ac
    ULONG TxFsContext;                                                      //0x1d0
    //struct _GDI_TEB_BATCH GdiTebBatch;                                      //0x1d4
    struct _CLIENT_ID RealClientId;                                         //0x6b4
    VOID* GdiCachedProcessHandle;                                           //0x6bc
    ULONG GdiClientPID;                                                     //0x6c0
    ULONG GdiClientTID;                                                     //0x6c4
    VOID* GdiThreadLocalInfo;                                               //0x6c8
    ULONG Win32ClientInfo[62];                                              //0x6cc
    VOID* glDispatchTable[233];                                             //0x7c4
    ULONG glReserved1[29];                                                  //0xb68
    VOID* glReserved2;                                                      //0xbdc
    VOID* glSectionInfo;                                                    //0xbe0
    VOID* glSection;                                                        //0xbe4
    VOID* glTable;                                                          //0xbe8
    VOID* glCurrentRC;                                                      //0xbec
    VOID* glContext;                                                        //0xbf0
    ULONG LastStatusValue;                                                  //0xbf4
    struct _UNICODE_STRING StaticUnicodeString;                             //0xbf8
    WCHAR StaticUnicodeBuffer[261];                                         //0xc00
    VOID* DeallocationStack;                                                //0xe0c
    VOID* TlsSlots[64];                                                     //0xe10
    struct _LIST_ENTRY TlsLinks;                                            //0xf10
    VOID* Vdm;                                                              //0xf18
    VOID* ReservedForNtRpc;                                                 //0xf1c
    VOID* DbgSsReserved[2];                                                 //0xf20
    ULONG HardErrorMode;                                                    //0xf28
    VOID* Instrumentation[9];                                               //0xf2c
    struct _GUID ActivityId;                                                //0xf50
    VOID* SubProcessTag;                                                    //0xf60
    VOID* EtwLocalData;                                                     //0xf64
    VOID* EtwTraceData;                                                     //0xf68
    VOID* WinSockData;                                                      //0xf6c
    ULONG GdiBatchCount;                                                    //0xf70
    union
    {
        struct _PROCESSOR_NUMBER CurrentIdealProcessor;                     //0xf74
        ULONG IdealProcessorValue;                                          //0xf74
        struct
        {
            UCHAR ReservedPad0;                                             //0xf74
            UCHAR ReservedPad1;                                             //0xf75
            UCHAR ReservedPad2;                                             //0xf76
            UCHAR IdealProcessor;                                           //0xf77
        };
    };
    ULONG GuaranteedStackBytes;                                             //0xf78
    VOID* ReservedForPerf;                                                  //0xf7c
    VOID* ReservedForOle;                                                   //0xf80
    ULONG WaitingOnLoaderLock;                                              //0xf84
    VOID* SavedPriorityState;                                               //0xf88
    ULONG SoftPatchPtr1;                                                    //0xf8c
    VOID* ThreadPoolData;                                                   //0xf90
    VOID** TlsExpansionSlots;                                               //0xf94
    ULONG MuiGeneration;                                                    //0xf98
    ULONG IsImpersonating;                                                  //0xf9c
    VOID* NlsCache;                                                         //0xfa0
    VOID* pShimData;                                                        //0xfa4
    ULONG HeapVirtualAffinity;                                              //0xfa8
    VOID* CurrentTransactionHandle;                                         //0xfac
    struct _TEB_ACTIVE_FRAME* ActiveFrame;                                  //0xfb0
    VOID* FlsData;                                                          //0xfb4
    VOID* PreferredLanguages;                                               //0xfb8
    VOID* UserPrefLanguages;                                                //0xfbc
    VOID* MergedPrefLanguages;                                              //0xfc0
    ULONG MuiImpersonation;                                                 //0xfc4
    union
    {
        volatile USHORT CrossTebFlags;                                      //0xfc8
        USHORT SpareCrossTebBits:16;                                        //0xfc8
    };
    union
    {
        USHORT SameTebFlags;                                                //0xfca
        struct
        {
            USHORT SafeThunkCall:1;                                         //0xfca
            USHORT InDebugPrint:1;                                          //0xfca
            USHORT HasFiberData:1;                                          //0xfca
            USHORT SkipThreadAttach:1;                                      //0xfca
            USHORT WerInShipAssertCode:1;                                   //0xfca
            USHORT RanProcessInit:1;                                        //0xfca
            USHORT ClonedThread:1;                                          //0xfca
            USHORT SuppressDebugMsg:1;                                      //0xfca
            USHORT DisableUserStackWalk:1;                                  //0xfca
            USHORT RtlExceptionAttached:1;                                  //0xfca
            USHORT InitialThread:1;                                         //0xfca
            USHORT SpareSameTebBits:5;                                      //0xfca
        };
    };
    VOID* TxnScopeEnterCallback;                                            //0xfcc
    VOID* TxnScopeExitCallback;                                             //0xfd0
    VOID* TxnScopeContext;                                                  //0xfd4
    ULONG LockCount;                                                        //0xfd8
    ULONG SpareUlong0;                                                      //0xfdc
    VOID* ResourceRetValue;                                                 //0xfe0
} LDR_TEB_A, *PLDR_TEB_A;

//0x460 bytes (sizeof)
typedef struct LDR_PEB_A
{
    UCHAR InheritedAddressSpace;                                            //0x0
    UCHAR ReadImageFileExecOptions;                                         //0x1
    UCHAR BeingDebugged;                                                    //0x2
    union
    {
        UCHAR BitField;                                                     //0x3
        struct
        {
            UCHAR ImageUsesLargePages:1;                                    //0x3
            UCHAR IsProtectedProcess:1;                                     //0x3
            UCHAR IsImageDynamicallyRelocated:1;                            //0x3
            UCHAR SkipPatchingUser32Forwarders:1;                           //0x3
            UCHAR IsPackagedProcess:1;                                      //0x3
            UCHAR IsAppContainer:1;                                         //0x3
            UCHAR IsProtectedProcessLight:1;                                //0x3
            UCHAR IsLongPathAwareProcess:1;                                 //0x3
        };
    };
    VOID* Mutant;                                                           //0x4
    VOID* ImageBaseAddress;                                                 //0x8
    struct _PEB_LDR_DATA* Ldr;                                              //0xc
    struct _RTL_USER_PROCESS_PARAMETERS* ProcessParameters;                 //0x10
    VOID* SubSystemData;                                                    //0x14
    VOID* ProcessHeap;                                                      //0x18
    struct _RTL_CRITICAL_SECTION* FastPebLock;                              //0x1c
    union _SLIST_HEADER* volatile AtlThunkSListPtr;                         //0x20
    VOID* IFEOKey;                                                          //0x24
    union
    {
        ULONG CrossProcessFlags;                                            //0x28
        struct
        {
            ULONG ProcessInJob:1;                                           //0x28
            ULONG ProcessInitializing:1;                                    //0x28
            ULONG ProcessUsingVEH:1;                                        //0x28
            ULONG ProcessUsingVCH:1;                                        //0x28
            ULONG ProcessUsingFTH:1;                                        //0x28
            ULONG ProcessPreviouslyThrottled:1;                             //0x28
            ULONG ProcessCurrentlyThrottled:1;                              //0x28
            ULONG ReservedBits0:25;                                         //0x28
        };
    };
    union
    {
        VOID* KernelCallbackTable;                                          //0x2c
        VOID* UserSharedInfoPtr;                                            //0x2c
    };
    ULONG SystemReserved[1];                                                //0x30
    union _SLIST_HEADER* volatile AtlThunkSListPtr32;                       //0x34
    VOID* ApiSetMap;                                                        //0x38
    ULONG TlsExpansionCounter;                                              //0x3c
    VOID* TlsBitmap;                                                        //0x40
    ULONG TlsBitmapBits[2];                                                 //0x44
    VOID* ReadOnlySharedMemoryBase;                                         //0x4c
    VOID* SharedData;                                                       //0x50
    VOID** ReadOnlyStaticServerData;                                        //0x54
    VOID* AnsiCodePageData;                                                 //0x58
    VOID* OemCodePageData;                                                  //0x5c
    VOID* UnicodeCaseTableData;                                             //0x60
    ULONG NumberOfProcessors;                                               //0x64
    ULONG NtGlobalFlag;                                                     //0x68
    union _LARGE_INTEGER CriticalSectionTimeout;                            //0x70
    ULONG HeapSegmentReserve;                                               //0x78
    ULONG HeapSegmentCommit;                                                //0x7c
    ULONG HeapDeCommitTotalFreeThreshold;                                   //0x80
    ULONG HeapDeCommitFreeBlockThreshold;                                   //0x84
    ULONG NumberOfHeaps;                                                    //0x88
    ULONG MaximumNumberOfHeaps;                                             //0x8c
    VOID** ProcessHeaps;                                                    //0x90
    VOID* GdiSharedHandleTable;                                             //0x94
    VOID* ProcessStarterHelper;                                             //0x98
    ULONG GdiDCAttributeList;                                               //0x9c
    struct _RTL_CRITICAL_SECTION* LoaderLock;                               //0xa0
    ULONG OSMajorVersion;                                                   //0xa4
    ULONG OSMinorVersion;                                                   //0xa8
    USHORT OSBuildNumber;                                                   //0xac
    USHORT OSCSDVersion;                                                    //0xae
    ULONG OSPlatformId;                                                     //0xb0
    ULONG ImageSubsystem;                                                   //0xb4
    ULONG ImageSubsystemMajorVersion;                                       //0xb8
    ULONG ImageSubsystemMinorVersion;                                       //0xbc
    ULONG ActiveProcessAffinityMask;                                        //0xc0
    ULONG GdiHandleBuffer[34];                                              //0xc4
    VOID (*PostProcessInitRoutine)();                                       //0x14c
    VOID* TlsExpansionBitmap;                                               //0x150
    ULONG TlsExpansionBitmapBits[32];                                       //0x154
    ULONG SessionId;                                                        //0x1d4
    union _ULARGE_INTEGER AppCompatFlags;                                   //0x1d8
    union _ULARGE_INTEGER AppCompatFlagsUser;                               //0x1e0
    VOID* pShimData;                                                        //0x1e8
    VOID* AppCompatInfo;                                                    //0x1ec
    struct _UNICODE_STRING CSDVersion;                                      //0x1f0
    struct _ACTIVATION_CONTEXT_DATA* ActivationContextData;                 //0x1f8
    struct _ASSEMBLY_STORAGE_MAP* ProcessAssemblyStorageMap;                //0x1fc
    struct _ACTIVATION_CONTEXT_DATA* SystemDefaultActivationContextData;    //0x200
    struct _ASSEMBLY_STORAGE_MAP* SystemAssemblyStorageMap;                 //0x204
    ULONG MinimumStackCommit;                                               //0x208
    struct _FLS_CALLBACK_INFO* FlsCallback;                                 //0x20c
    struct _LIST_ENTRY FlsListHead;                                         //0x210
    VOID* FlsBitmap;                                                        //0x218
    ULONG FlsBitmapBits[4];                                                 //0x21c
    ULONG FlsHighIndex;                                                     //0x22c
    VOID* WerRegistrationData;                                              //0x230
    VOID* WerShipAssertPtr;                                                 //0x234
    VOID* pUnused;                                                          //0x238
    VOID* pImageHeaderHash;                                                 //0x23c
    union
    {
        ULONG TracingFlags;                                                 //0x240
        struct
        {
            ULONG HeapTracingEnabled:1;                                     //0x240
            ULONG CritSecTracingEnabled:1;                                  //0x240
            ULONG LibLoaderTracingEnabled:1;                                //0x240
            ULONG SpareTracingBits:29;                                      //0x240
        };
    };
    ULONGLONG CsrServerReadOnlySharedMemoryBase;                            //0x248
    ULONG TppWorkerpListLock;                                               //0x250
    struct _LIST_ENTRY TppWorkerpList;                                      //0x254
    VOID* WaitOnAddressHashTable[128];                                      //0x25c
} LDR_PEB_A, *PLDR_PEB_A;

typedef struct _LDR_RTL_HEAP_DEFINITION {

    ULONG                   Length;
    ULONG                   Unknown1;
    ULONG                   Unknown2;
    ULONG                   Unknown3;
    ULONG                   Unknown4;
    ULONG                   Unknown5;
    ULONG                   Unknown6;
    ULONG                   Unknown7;
    ULONG                   Unknown8;
    ULONG                   Unknown9;
    ULONG                   Unknown10;
    ULONG                   Unknown11;
    ULONG                   Unknown12;

} LDR_RTL_HEAP_DEFINITION, *PLDR_RTL_HEAP_DEFINITION;

typedef struct _LDR_INITIAL_TEB {
    PVOID                StackBase;
    PVOID                StackLimit;
    PVOID                StackCommit;
    PVOID                StackCommitMax;
    PVOID                StackReserved;
} LDR_INITIAL_TEB, *PLDR_INITIAL_TEB;



#include <windows.h>

typedef void *HMEMORYMODULE;

typedef void *HCUSTOMMODULE;

typedef LPVOID (*CustomAllocFunc)(LPVOID, SIZE_T, DWORD, DWORD, void*);
typedef BOOL (*CustomFreeFunc)(LPVOID, SIZE_T, DWORD, void*);
typedef HCUSTOMMODULE (*CustomLoadLibraryFunc)(LPCSTR, void *);
typedef FARPROC (*CustomGetProcAddressFunc)(HCUSTOMMODULE, LPCSTR, void *);
typedef void (*CustomFreeLibraryFunc)(HCUSTOMMODULE, void *);

HMEMORYMODULE MemoryLoadLibrary(PVOID pFileBuffer, SIZE_T zFileSize, BOOL isBeacon);

#endif //DLLMEMLDR_LIBRARY_H
