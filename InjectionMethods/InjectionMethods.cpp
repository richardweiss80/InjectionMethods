// InjectionMethods.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"
#include "injections.h"

int main(int argc, const char* argv[])
{
	DWORD pid = atoi(argv[1]);
	injectShellCode(pid);
}

