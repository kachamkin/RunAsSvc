#pragma once

#include <tchar.h>
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <atlconv.h>
#include <string>

#define SERVICE_NAME (LPTSTR)_T("RunAsSvc")
#define DISPLAY_NAME _T("Run As Service")

using namespace std;

SERVICE_STATUS serviceStatus;
SERVICE_STATUS_HANDLE serviceStatusHandle;
HANDLE stopEvent;

//TCHAR fileName[256];

SOCKET listen_socket;

BOOL Decrypt(LPTSTR base64str);
void addLogMessage(const TCHAR* a);
void LaunchProcess(LPTSTR cmdLine);
void CleanUp();
void Listen(LPTSTR portAtStart = NULL);
void EnumSessionsAndProcesses();
void EnumProcesses(DWORD* sid);
LPWSTR GetHomeDirectory();
void GetUsers(wstring* output);
void GetGroups(wstring* output);
void GetLocalGroups(wstring* output);


