#include "pch.h"
#include "helper.h"


int Error(const char* description) {
	printf("[E] ERROR: %s - Code: %d\n", description, ::GetLastError());
	return 1;
}

void Info(const char sign, const char* description) {
	printf("[%c] %s \n", sign, description);
}

BOOL startProcess() {
	STARTUPINFO si = { sizeof(si) };
	PROCESS_INFORMATION pi;
	WCHAR name[] = L"explorer";

	BOOL success = ::CreateProcess(nullptr, name, nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi);

	::CloseHandle(pi.hProcess);
	::CloseHandle(pi.hThread);

	return success;
}

DWORD getProcessPID() {
	HANDLE hSnapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		return Error("failed to create Snapshot in (f)findProcess");
	}

	PROCESSENTRY32 pe;
	pe.dwSize = sizeof(pe); // pe.dwSize = sizeof(PROCESSENTRY32)

	if (!::Process32First(hSnapshot, &pe)) {
		return Error("failed in Process32First in (f)findProcess");
	}

	DWORD pid = -1;

	do {
		if (wcscmp(L"explorer.exe", pe.szExeFile) == 0) {
			pid = pe.th32ProcessID;
			break;
		}
	} while (::Process32Next(hSnapshot, &pe));

	::CloseHandle(hSnapshot);
	return pid;

}