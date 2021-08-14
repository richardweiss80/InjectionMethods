// InjectionMethods.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"
#include "injections.h"
#include "helper.h"

int main()
{
	startProcess();
	Sleep(1000);
	DWORD pid = getProcessPID();

	if (pid == -1) {
		Error("No Process found");
		return 1;
	}

	injectShellCode(pid);
}

