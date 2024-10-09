//
// Created by scrub on 10/8/2024.
//
#include <stdio.h>
#include <windows.h>

#include "../DllMemLdr.h"

#define PID
#define testDll "C:\\path\\to\\fun.dll"

int main(void) {
    HANDLE      hFile = NULL;
    PVOID       pBuffer = NULL;
    DWORD       dwFileSize = 0;
    DWORD       dwBytesRead = 0;

    hFile = CreateFileA(testDll, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (INVALID_HANDLE_VALUE == hFile) {
        printf("[!] Invalid File Handle %lu\n", GetLastError());
        return -1;
    }

    dwFileSize = GetFileSize(hFile, 0);
    printf("[+] %s File Size: %lu\n", testDll, dwFileSize);

    pBuffer = LocalAlloc(LPTR, dwFileSize);

    if (!ReadFile(hFile, pBuffer, dwFileSize, &dwBytesRead, 0)) {
        printf("[!] Failed to ReadFile %ld\n", GetLastError());
        return -1;
    }
    printf("[+] File Buffer %p\n", pBuffer);


    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
    if (NULL == hProcess) {
        printf("[!] OpenProcess Failed %lu\n", GetLastError());
    }

    MemLdrEx(hProcess, pBuffer);

}
