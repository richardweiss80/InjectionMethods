// dllmain.cpp : Definiert den Einstiegspunkt für die DLL-Anwendung.
#include "pch.h"

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        ::DisableThreadLibraryCalls(hModule); // Disables reason parameters relaed to threads
        WCHAR text[128];
        ::StringCchPrintf(text, _countof(text), L"PID: %u", ::GetCurrentProcessId());
        MessageBox(0, text, L"Information", MB_ICONINFORMATION);
        break;
    case DLL_THREAD_ATTACH:
        // Not Used
        MessageBox(0, L"DLL_Thread_Attach", L"Information", MB_ICONINFORMATION);
        break;
    case DLL_THREAD_DETACH:
        // Not Used
        MessageBox(0, L"DLL_Thread_Detach", L"Information", MB_ICONINFORMATION);
        break;
    case DLL_PROCESS_DETACH:
        MessageBox(0, L"DLL_Process_Detach", L"Information", MB_ICONINFORMATION);
        break;
    }
    return TRUE;
}

