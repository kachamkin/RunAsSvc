// dllmain.cpp : Определяет точку входа для приложения DLL.
#include "pch.h"
#include <easyhook.h> 
#include <tlhelp32.h>

#define SERVICE_NAME L"runassvc.exe"
#define DISPLAY_NAME L"Run As Service"

extern "C" void __declspec(dllexport) __stdcall NativeInjectionEntryPoint(REMOTE_ENTRY_INFO * inRemoteInfo);

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

LPWSTR ToLower(LPWSTR pStr)
{
	for (int i = 0; TRUE; i++)
	{
		LPWSTR pChar = pStr + i;
		if (*pChar == L'\0')
			break;
		else if (i == 259)
		{
			*pChar = L'\0';
			break;
		}
		else
			*pChar = towlower(*pChar);
	}
	return pStr;
}

DWORD GetCurProcID(LPCWSTR procName = SERVICE_NAME)
{
	DWORD id = 0;

	PROCESSENTRY32 entry = {};
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (Process32First(snapshot, &entry))
	{
		do
		{
			if (!wcscmp(ToLower(entry.szExeFile), procName))
			{
				id = entry.th32ProcessID;
				break;
			}
		} 
		while (Process32Next(snapshot, &entry));
	}

	CloseHandle(snapshot);

	return id;
}

void addLogMessage(const TCHAR* a)
{
	HANDLE log = RegisterEventSource(NULL, DISPLAY_NAME);
	if (log)
	{
		ReportEvent(log, EVENTLOG_INFORMATION_TYPE, 0, 0, NULL, 1, 0, &a, NULL);
		DeregisterEventSource(log);
	};
}

BOOL WINAPI ShadowTerminateProcess(HANDLE hProcess, UINT uiExitCode)
{
	if (GetProcessId(hProcess) == GetCurProcID())
		return TRUE;
	else
		return TerminateProcess(hProcess, uiExitCode);
}

void __stdcall NativeInjectionEntryPoint(REMOTE_ENTRY_INFO* inRemoteInfo)
{
	// Perform hooking
	HOOK_TRACE_INFO hHook = { NULL }; // keep track of our hook

		// Install the hook
	if (FAILED(LhInstallHook(
		TerminateProcess,
		ShadowTerminateProcess,
		NULL,
		&hHook)))
			addLogMessage(L"Failed to install hook");

	// If the threadId in the ACL is set to 0,
	// then internally EasyHook uses GetCurrentThreadId()
	ULONG ACLEntries[1] = { 0 };

	// Disable the hook for the provided threadIds, enable for all others
	LhSetExclusiveACL(ACLEntries, 1, &hHook);

	return;
}



