#include "DllMemLdr.h"

#include <stdio.h>


WCHAR wLdrntdll[] = {'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l', '\0'};
WCHAR cLdrAllocateVirtualMemory[] = {'N', 't', 'A', 'l', 'l', 'o', 'c', 'a', 't', 'e', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', '\0'};
WCHAR cLdrProtectVirtualMemory[] = {'N', 't', 'P', 'r', 'o', 't', 'e', 'c', 't', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', '\0'};
WCHAR cLdrFreeVirtualMemory[] = {'N', 't', 'F', 'r', 'e', 'e', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', '\0'};

LDR_API ldrApi = { 0 };
PLDR_API API = &ldrApi;


static inline size_t AlignValueUp(size_t value, size_t alignment) {
    return (value + alignment - 1) & ~(alignment - 1);
}

static inline uintptr_t
AlignValueDown(uintptr_t value, uintptr_t alignment) {
    return value & ~(alignment - 1);
}

static inline LPVOID
AlignAddressDown(LPVOID address, uintptr_t alignment) {
    return (LPVOID) AlignValueDown((uintptr_t) address, alignment);
}

static inline void*
OffsetPointer(void* data, ptrdiff_t offset) {
    return (void*) ((uintptr_t) data + offset);
}

// Used for checking case-sensitive library names
BOOL IsStringEqual (IN LPCWSTR Str1, IN LPCWSTR Str2) {

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

HMODULE GetModuleHandleC(IN LPCWSTR szModuleName) {

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
            if (IsStringEqual(pDte->FullDllName.Buffer, szModuleName)) {
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

PVOID GetProcAddressC(HMODULE hModule, LPCWSTR lpProcName) {

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

VOID FreePointerList(POINTER_LIST *head)
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

static SIZE_T
GetRealSectionSize(PIMAGE_NT_HEADERS pNtHeaders, PIMAGE_SECTION_HEADER section) {
    DWORD size = section->SizeOfRawData;
    if (size == 0) {
        if (section->Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) {
            size = pNtHeaders->OptionalHeader.SizeOfInitializedData;
        } else if (section->Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) {
            size = pNtHeaders->OptionalHeader.SizeOfUninitializedData;
        }
    }
    return (SIZE_T) size;
}

BOOL LoadLdrAPI() {
    // Virtual Memory
    API->VirtualAlloc = (fnLdrNtAllocateVirtualMemory)GetProcAddressC(GetModuleHandleC(wLdrntdll), cLdrAllocateVirtualMemory);
    if (API->VirtualAlloc == NULL) {
        return FALSE;
    }
    API->VirtualProtect = (fnLdrNtProtectVirtualMemory)GetProcAddressC(GetModuleHandleC(wLdrntdll), cLdrProtectVirtualMemory);
    if (API->VirtualProtect == NULL) {
        return FALSE;
    }
    API->VirtualFree = (fnLdrNtFreeVirtualMemory)GetProcAddressC(GetModuleHandleC(wLdrntdll), cLdrFreeVirtualMemory);
    if (API->VirtualFree == NULL) {
        return FALSE;
    }
    return TRUE;
}

BOOL CopySections(HANDLE hProcess, const unsigned char *data, PIMAGE_NT_HEADERS old_headers, PVOID pDllBuffer, PIMAGE_NT_HEADERS pNtHeaders)
{
    int i, section_size;
    unsigned char *dest;
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(pNtHeaders);
    for (i=0; i<pNtHeaders->FileHeader.NumberOfSections; i++, section++) {
        if (section->SizeOfRawData == 0) {
            section_size = old_headers->OptionalHeader.SectionAlignment;

            if (section_size > 0) {
                dest = (pDllBuffer + section->VirtualAddress);
                SIZE_T zSectionSize = section_size;
                LDR_ALLOCATE_VIRTUAL_MEMORY(hProcess, &dest, &zSectionSize, MEM_COMMIT, PAGE_READWRITE);
                if (dest == NULL) {
                    return FALSE;
                }
                dest = pDllBuffer + section->VirtualAddress;
                section->Misc.PhysicalAddress = (DWORD) ((uintptr_t) dest & 0xffffffff);
                _LDR_MEMSET_(dest, 0, section_size);
            }

            // section is empty
            continue;
        }

        dest = (pDllBuffer + section->VirtualAddress);
        SIZE_T zSectionSize = section->SizeOfRawData;
        LDR_ALLOCATE_VIRTUAL_MEMORY(hProcess, &dest, &zSectionSize, MEM_COMMIT, PAGE_READWRITE);

        if (dest == NULL) {
            return FALSE;
        }

        dest = pDllBuffer + section->VirtualAddress;
        _LDR_MEMCPY_(dest, data + section->PointerToRawData, section->SizeOfRawData);
        section->Misc.PhysicalAddress = (DWORD) ((uintptr_t) dest & 0xffffffff);
    }

    return TRUE;
}

static BOOL
PerformBaseRelocation(PVOID pDllBuffer, PIMAGE_NT_HEADERS pNtHeaders, ptrdiff_t delta)
{
    PIMAGE_BASE_RELOCATION relocation;

    PIMAGE_DATA_DIRECTORY directory = GET_HEADER_DICTIONARY(pNtHeaders, IMAGE_DIRECTORY_ENTRY_BASERELOC);
    if (directory->Size == 0) {
        return (delta == 0);
    }

    relocation = (PIMAGE_BASE_RELOCATION) (pDllBuffer + directory->VirtualAddress);
    for (; relocation->VirtualAddress > 0; ) {
        DWORD i;
        unsigned char *dest = pDllBuffer + relocation->VirtualAddress;
        unsigned short *relInfo = (unsigned short*) OffsetPointer(relocation, IMAGE_SIZEOF_BASE_RELOCATION);
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


BOOL BuildImportTable(PVOID pDllBuffer, PIMAGE_NT_HEADERS pNtHeaders)
{

    HMODULE* hModules = (HMODULE*)malloc(sizeof(HMODULE));
    DWORD   dwModuleCount = 0;
    BOOL result = TRUE;

    PIMAGE_DATA_DIRECTORY pDataDir = GET_HEADER_DICTIONARY(pNtHeaders, IMAGE_DIRECTORY_ENTRY_IMPORT);
    if (pDataDir->Size == 0) {
        result = TRUE;
    }

    PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR) (pDllBuffer + pDataDir->VirtualAddress);
    for (; !IsBadReadPtr(pImportDesc, sizeof(IMAGE_IMPORT_DESCRIPTOR)) && pImportDesc->Name; pImportDesc++) {
        uintptr_t *thunkRef;
        FARPROC *funcRef;
        HMODULE hModule = LoadLibrary((LPCSTR) (pDllBuffer + pImportDesc->Name));
        if (hModule == NULL) {
            SetLastError(ERROR_MOD_NOT_FOUND);
            result = FALSE;
            break;
        }

        HMODULE* hTmp = (HMODULE *) realloc(hModules, (dwModuleCount+1)*(sizeof(HMODULE)));
        if (hTmp == NULL) {
            SetLastError(ERROR_OUTOFMEMORY);
            result = FALSE;
            break;
        }
        hModules = hTmp;

        hModules[dwModuleCount++] = hModule;
        if (pImportDesc->OriginalFirstThunk) {
            thunkRef = (uintptr_t *) (pDllBuffer + pImportDesc->OriginalFirstThunk);
            funcRef = (FARPROC *) (pDllBuffer + pImportDesc->FirstThunk);
        } else {
            // no hint table
            thunkRef = (uintptr_t *) (pDllBuffer + pImportDesc->FirstThunk);
            funcRef = (FARPROC *) (pDllBuffer + pImportDesc->FirstThunk);
        }
        for (; *thunkRef; thunkRef++, funcRef++) {
            if (IMAGE_SNAP_BY_ORDINAL(*thunkRef)) {
                *funcRef = GetProcAddress(hModule, (LPCSTR)IMAGE_ORDINAL(*thunkRef));
            } else {
                PIMAGE_IMPORT_BY_NAME thunkData = (PIMAGE_IMPORT_BY_NAME) (pDllBuffer + (*thunkRef));
                *funcRef = GetProcAddress(hModule, (LPCSTR)&thunkData->Name);
            }
            if (*funcRef == 0) {
                result = FALSE;
                break;
            }
        }

        if (!result) {
            FreeLibrary(hModule);
            SetLastError(ERROR_PROC_NOT_FOUND);
            break;
        }
    }
    for (DWORD i =0; i <+ dwModuleCount; i++) {
        FreeLibrary(hModules[i]);
    }
    free(hModules);

    return result;
}



BOOL FinalizeSection(HANDLE hProcess, PIMAGE_NT_HEADERS pNtHeaders, PSECTIONFINALIZEDATA sectionData, DWORD dwPageSize) {
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
             pNtHeaders->OptionalHeader.SectionAlignment == dwPageSize ||
             (sectionData->size % dwPageSize) == 0)
           ) {
            // Only allowed to decommit whole pages
            PVOID lpSectionFreeAddress = sectionData->address;
            DWORD dwSectionSize = sectionData->size;
            LDR_FREE_VIRTUAL_MEMORY(hProcess, &lpSectionFreeAddress, &dwSectionSize, MEM_DECOMMIT);
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
    SIZE_T zSectionSize = sectionData->size;
    LPVOID lpSectionBuffer = sectionData->address;
    if (LDR_PROTECT_VIRTUAL_MEMORY(hProcess, &lpSectionBuffer, &zSectionSize, protect, &oldProtect)) {
        return FALSE;
    }
    return TRUE;
}


BOOL FinalizeSections(HANDLE hProcess, PIMAGE_NT_HEADERS pNtHeaders, DWORD dwPageSize)
{
    int i;
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(pNtHeaders);
    uintptr_t imageOffset = ((uintptr_t) pNtHeaders->OptionalHeader.ImageBase & 0xffffffff00000000);
    SECTIONFINALIZEDATA sectionData;
    sectionData.address = (LPVOID)((uintptr_t)section->Misc.PhysicalAddress | imageOffset);
    sectionData.alignedAddress = AlignAddressDown(sectionData.address, dwPageSize);
    sectionData.size = GetRealSectionSize(pNtHeaders, section);
    sectionData.characteristics = section->Characteristics;
    sectionData.last = FALSE;
    section++;

    // loop through all sections and change access flags
    for (i=1; i<pNtHeaders->FileHeader.NumberOfSections; i++, section++) {
        LPVOID sectionAddress = (LPVOID)((uintptr_t)section->Misc.PhysicalAddress | imageOffset);
        LPVOID alignedAddress = AlignAddressDown(sectionAddress, dwPageSize);
        SIZE_T sectionSize = GetRealSectionSize(pNtHeaders, section);
        // Combine access flags of all sections that share a page
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

        if (!FinalizeSection(hProcess, pNtHeaders, &sectionData, dwPageSize)) {
            return FALSE;
        }
        sectionData.address = sectionAddress;
        sectionData.alignedAddress = alignedAddress;
        sectionData.size = sectionSize;
        sectionData.characteristics = section->Characteristics;
    }
    sectionData.last = TRUE;
    if (!FinalizeSection(hProcess, pNtHeaders, &sectionData, dwPageSize)) {
        return FALSE;
    }
    return TRUE;
}


BOOL ExecuteTLS(PVOID pDllBuffer, PIMAGE_NT_HEADERS pNtHeaders)
{
    PIMAGE_TLS_DIRECTORY tls;
    PIMAGE_TLS_CALLBACK* callback;

    PIMAGE_DATA_DIRECTORY directory = GET_HEADER_DICTIONARY(pNtHeaders, IMAGE_DIRECTORY_ENTRY_TLS);
    if (directory->VirtualAddress == 0) {
        return TRUE;
    }


    tls = (PIMAGE_TLS_DIRECTORY) (pDllBuffer + directory->VirtualAddress);
    callback = (PIMAGE_TLS_CALLBACK *) tls->AddressOfCallBacks;
    if (callback) {
        while (*callback) {
            (*callback)((LPVOID) pDllBuffer, DLL_PROCESS_ATTACH, NULL);
            callback++;
        }
    }
    return TRUE;
}

BOOL MemLdrEx(HANDLE hProcess, PVOID pPE) {

    if (!LoadLdrAPI()) {
        return FALSE;
    }
    POINTER_LIST *blockedMemory = NULL;
    BOOL isRelocated = FALSE;

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pPE;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return FALSE;
    }
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(pPE + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return FALSE;
    }

    PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)(pPE + pDosHeader->e_lfanew + sizeof(DWORD));

    PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)(pPE + pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS));

    // Get System info for page size (for AlignValueUp)
    SYSTEM_INFO sysInfo;
    GetNativeSystemInfo(&sysInfo);

    // Allocate memory from DLL file size
    SIZE_T zAlignedMemorySize = (SIZE_T)AlignValueUp(pNtHeaders->OptionalHeader.SizeOfImage, sysInfo.dwPageSize);
    LPVOID pDllBuffer = NULL;
    LDR_ALLOCATE_VIRTUAL_MEMORY(hProcess, &pDllBuffer, &zAlignedMemorySize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE) ;

    // Memory block may not span 4 GB boundaries.
    while ((((uintptr_t) pDllBuffer) >> 32) < (((uintptr_t) (pDllBuffer + zAlignedMemorySize)) >> 32)) {
        POINTER_LIST *node = (POINTER_LIST*) malloc(sizeof(POINTER_LIST));
        if (!node) {
            VirtualFree(pDllBuffer, 0, MEM_RELEASE);
            FreePointerList(blockedMemory);
            SetLastError(ERROR_OUTOFMEMORY);
            return FALSE;
        }

        node->next = blockedMemory;
        node->address = pDllBuffer;
        blockedMemory = node;

        LDR_ALLOCATE_VIRTUAL_MEMORY(hProcess, &pDllBuffer, &zAlignedMemorySize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

        if (pDllBuffer == NULL) {
            FreePointerList(blockedMemory);
            SetLastError(ERROR_OUTOFMEMORY);
            return FALSE;
        }
    }

    // Commit memory for PE headers inside pDllMemory
    LPVOID pHeadersBuffer = NULL;
    SIZE_T zSizeOfHeaders = pNtHeaders->OptionalHeader.SizeOfHeaders;
    LDR_ALLOCATE_VIRTUAL_MEMORY(hProcess, &pHeadersBuffer, &zSizeOfHeaders, MEM_COMMIT, PAGE_READWRITE);

    // Copy Headers to memory
    _LDR_MEMCPY_(pHeadersBuffer, pDosHeader, pNtHeaders->OptionalHeader.SizeOfHeaders);

    // Update & Copy New NT Header
    PIMAGE_NT_HEADERS pNewNtHeaders = (PIMAGE_NT_HEADERS)&((const unsigned char *)(pHeadersBuffer))[pDosHeader->e_lfanew];
    // Check if New Optional Header was copied successfully
    if (IMAGE_NT_SIGNATURE != pNewNtHeaders->Signature) {
        return FALSE;
    }
    // Update new Optional Header with Image base address.
    pNewNtHeaders->OptionalHeader.ImageBase = (uintptr_t)pDllBuffer;

    // Copy Sections CopySections(const unsigned char *data, /*size_t size,*/ PIMAGE_NT_HEADERS old_headers, PVOID pDllBuffer, PIMAGE_NT_HEADERS pNtHeaders)
    if (!CopySections(hProcess, pPE, pNtHeaders, pDllBuffer, pNewNtHeaders)) {
        return FALSE;
    }

    // adjust base address of imported data
    ptrdiff_t locationDelta = (ptrdiff_t)(pNewNtHeaders->OptionalHeader.ImageBase - pNtHeaders->OptionalHeader.ImageBase);
    if (locationDelta != 0) {
        isRelocated = PerformBaseRelocation(pDllBuffer, pNtHeaders, locationDelta);
    } else {
        isRelocated = TRUE;
    }
    if (!BuildImportTable(pDllBuffer, pNewNtHeaders)) {
        return FALSE;
    }
    // BOOL FinalizeSections(PIMAGE_NT_HEADERS pNtHeaders, DWORD dwPageSize)
    if (!FinalizeSections(hProcess, pNewNtHeaders, sysInfo.dwPageSize)) {
        return FALSE;
    }
    if (!ExecuteTLS(pDllBuffer, pNewNtHeaders)) {
        return FALSE;
    }

    BOOL isDLL = (pNtHeaders->FileHeader.Characteristics & IMAGE_FILE_DLL) != 0;
    BOOL initialized = FALSE;
    ExeEntryProc exeEntry = {};

    // get entry point of loaded library
    if (pNewNtHeaders->OptionalHeader.AddressOfEntryPoint != 0) {
        if (isDLL) {
            DllEntryProc DllEntry = (DllEntryProc)(LPVOID)(pDllBuffer + pNewNtHeaders->OptionalHeader.AddressOfEntryPoint);
            // notify library about attaching to process
            BOOL successfull = (*DllEntry)((HINSTANCE)pDllBuffer, DLL_PROCESS_ATTACH, 0);
            if (!successfull) {
                SetLastError(ERROR_DLL_INIT_FAILED);
            }
            initialized = TRUE;
        } else {
            exeEntry = (ExeEntryProc)(LPVOID)(pDllBuffer + pNewNtHeaders->OptionalHeader.AddressOfEntryPoint);
        }
    } else {
        exeEntry = NULL;
    }

    return TRUE;

}

BOOL MemLdr(PVOID pPE) {
    if (!MemLdrEx(GetCurrentProcess(), pPE)) {
        return FALSE;
    }
    return TRUE;
}