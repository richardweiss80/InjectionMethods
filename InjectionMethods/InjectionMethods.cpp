// InjectionMethods.cpp: This function is used for calling the different injection methods
// This code shall not be used for illeagal purposes and is only mentioned for a better understaning in combination of the blog posts (at this time not public)and webinars
// Please do not hesitate to use this code for trainings, but mention the author: @rchrdwss. Thank you
// For better understanding all necessary part are inside the calles injection methods, even this leads not to using good coding practices

#include "pch.h"
#include "pe_injection_methods.h"
#include "dll_injection_methods.h"
#include "helper.h"

int main()
{
	 //This is only used to start WordPad as process to be inhected
	startProcess();
	Sleep(1000);
	DWORD pid = getProcessID();

	if (pid == -1) {
		Error("No Process found");
		return 1;
	}
	// injectShellCode(pid);
	// injectDLL(pid);
	injectPE(pid);
}

