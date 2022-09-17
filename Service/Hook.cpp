#include <Windows.h>
//#include <easyhook.h>
//#include <tlhelp32.h>
#include <string>
#include <WtsApi32.h>
//#include <AccCtrl.h>
//#include <AclAPI.h>

//#define MAX_IDS 128

using namespace std;

//extern HANDLE stopEvent;

//DWORD ids[MAX_IDS] = {0};
//int numIds = 0;
//
//void Tolower(wstring& s);
//void addLogMessage(const TCHAR* a);
LPWSTR GetHomeDirectory();
//
//bool Contains(DWORD* pArray, DWORD dwValue)
//{
//	for (int i = 0; i < numIds; i++)
//		if (*(pArray + i) == dwValue)
//			return true;
//
//	return false;
//}
//
//DWORD GetTaskMgrID(LPCWSTR procName = L"taskmgr.exe")
//{
//	if (numIds == MAX_IDS)
//		return 0;
//
//	DWORD id = 0;
//	
//	PROCESSENTRY32 entry = {};
//	entry.dwSize = sizeof(PROCESSENTRY32);
//
//	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
//
//	if (Process32First(snapshot, &entry))
//	{
//		do
//		{
//			wstring wsExeFile = entry.szExeFile;
//			Tolower(wsExeFile);
//			if (wsExeFile == procName)
//			{
//				if (!Contains(ids, entry.th32ProcessID))
//				{
//					id = entry.th32ProcessID;
//					ids[numIds] = id;
//					numIds++;
//					break;
//				}
//			}
//		} 
//		while (Process32Next(snapshot, &entry));
//	}
//
//	CloseHandle(snapshot);
//
//	return id;
//}
//
//void InjectHook()
//{
//	DWORD id = 0;
//	do
//	{
//		if (WaitForSingleObject(stopEvent, 0) == WAIT_OBJECT_0)
//			return;
//
//		if (numIds == MAX_IDS)
//		{
//			numIds = 0;
//			addLogMessage(L"Too many IDs");
//		}
//
//		id = GetTaskMgrID();
//		if (!id)
//			Sleep(500);
//	}
//	while (!id);
//
//	LPWSTR dir = GetHomeDirectory();
//	wstring wsDll = wstring(dir) + L"\\Hook.dll";
//	LPWSTR dllToInject = (LPWSTR)wsDll.data();
//	delete dir;
//
//	if (FAILED(RhInjectLibrary(
//		id,   // The process to inject into
//		0,           // ThreadId to wake up upon injection
//		EASYHOOK_INJECT_DEFAULT,
//		NULL, // 32-bit
//		dllToInject,		 // 64-bit
//		NULL, // data to send to injected DLL entry point
//		0// size of data to send
//	)))
//		addLogMessage((wstring(L"Failed to inject hook to taskmgr: ") + RtlGetLastErrorString()).data());
//
//	InjectHook();
//}


void CreateProcessInSession(DWORD sid, HANDLE hToken, const wstring& commandLine)
{
	HANDLE hDpToken(0);
	if (DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hDpToken))
	{
		if (SetTokenInformation(hDpToken, TokenSessionId, &sid, sizeof(sid)))
		{
			STARTUPINFO si;
			memset(&si, 0, sizeof(si));
			si.cb = sizeof(si);
			si.lpDesktop = (LPWSTR)L"Winsta0\\default";

			PROCESS_INFORMATION processInfo;
			memset(&processInfo, 0, sizeof(processInfo));

			if (CreateProcessAsUser(hDpToken, NULL, (LPWSTR)commandLine.data(), NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &processInfo))
			{
				CloseHandle(processInfo.hThread);
				CloseHandle(processInfo.hProcess);
			}
		}
		CloseHandle(hDpToken);
	}
} 

void EnumProcesses(DWORD* sid)
{
	HANDLE token = NULL;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &token))
		return;

	LPWSTR dir = GetHomeDirectory();
	wstring cmdLine = L"\"" + wstring(dir) + L"\\PrevTermCPP.exe\" " + to_wstring(GetCurrentProcessId());
	delete[] dir;

	BOOL createProcess = TRUE;
	PWTS_PROCESS_INFO procInfo = {};
	DWORD numProcesses = 0;
	DWORD level = 0;
	if (WTSEnumerateProcessesEx(WTS_CURRENT_SERVER_HANDLE, &level, *sid, (LPWSTR*)&procInfo, &numProcesses))
	{
		for (DWORD j = 0; j < numProcesses; j++)
		{
			if (wstring(procInfo[j].pProcessName) == L"PrevTermCPP.exe")
			{
				createProcess = FALSE;
				break;
			}
		}
		WTSFreeMemory(procInfo);
	}

	if (createProcess)
		CreateProcessInSession(*sid, token, cmdLine);

	CloseHandle(token);
}

void EnumSessionsAndProcesses()
{
	PWTS_SESSION_INFO sessinInfo = {};
	DWORD numSessions = 0;

	if (WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE, 0, 1, &sessinInfo, &numSessions))
	{
		for (DWORD i = 0; i < numSessions; i++)
		{
			if (sessinInfo[i].State == WTSActive)
				EnumProcesses(&sessinInfo[i].SessionId);
		}
		WTSFreeMemory(sessinInfo);
	}
}

