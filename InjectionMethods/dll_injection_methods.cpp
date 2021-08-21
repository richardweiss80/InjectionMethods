#include "pch.h"
#include "dll_injection_methods.h"
#include "helper.h"

/* There is no refactoring done in the functions for a better unerstanding of the different injection methods*/

void injectDLL(_In_ DWORD pid) {
    DWORD dwDesiredAccess = PROCESS_CREATE_THREAD | PROCESS_VM_WRITE | PROCESS_VM_OPERATION; // often seen: PROCESS_ALL_ACCESS;

    HANDLE hProcess;
    LPVOID ptrVirtAlloc = nullptr;

    static const UCHAR dllPath[] = "C:\\Users\\rwe\\Desktop\\Development\\InjectionMethods\\x64\\Debug\\InjectedDLL.dll";

    if (hProcess = ::OpenProcess(dwDesiredAccess, false, pid)) {
        _tprintf(_TEXT("[+] Opened process %i successfully: %i\n"), pid, hProcess);
        if (ptrVirtAlloc = ::VirtualAllocEx(hProcess, NULL, sizeof(dllPath), MEM_COMMIT, PAGE_READWRITE)) {
            _tprintf(_TEXT("[+] Allocated Memory successfully at: %p in sizeof %i bytes\n"), ptrVirtAlloc, sizeof(dllPath));

            DWORD tid;

            ::WriteProcessMemory(hProcess, ptrVirtAlloc, dllPath, sizeof(dllPath), NULL);
            _tprintf(_TEXT("[+] Wrote Path of DLL to Memory\n"));

            if (HANDLE hThread = ::CreateRemoteThread(hProcess,
                                                      NULL,
                                                      0,
                                                      (LPTHREAD_START_ROUTINE)::GetProcAddress(::GetModuleHandle(L"Kernel32.dll"),
                                                                                                                 "LoadLibraryA"),
                                                      ptrVirtAlloc,
                                                      0,
                                                      &tid))
            {
                _tprintf(_TEXT("[+] Created Remote Threat - ID: %d - HandleID: %i"), tid, hThread);

                if (WAIT_OBJECT_0 == ::WaitForSingleObject(hThread, 3000)) {
                    _tprintf(_TEXT("[+] Process exited normally.\n"));
                }

                ::CloseHandle(hThread);
            }
            ::VirtualFreeEx(hProcess, ptrVirtAlloc, 0, MEM_RELEASE);
        }
        ::CloseHandle(hProcess);
    }
    else {
        Error("Failed to open process!");
    }

}

