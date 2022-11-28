#include "header.h"

inline bool validatePort(char* port, char* arg)
{
	const int maxPortLen = 5;
	const int maxPortVal = 65535;

	strcpy(port, DEFAULT_PORT);

	if (arg != NULL)
	{
		if (strlen(arg) > maxPortLen)
		{
			addLogMessage((string("Invalid port number: ") + arg).data(), __FILE__, __LINE__);
			return false;
		}
		else
			strcpy(port, arg);
	}

	try
	{
		int nPort = stoi(port);
		if (!nPort || nPort > maxPortVal)
		{
			addLogMessage((string("Invalid port number: ") + port).data(), __FILE__, __LINE__);
			return false;
		}
	}
	catch (...)
	{
		addLogMessage((string("Invalid port number: ") + port).data(), __FILE__, __LINE__);
		return false;
	}

	return true;
}

inline void getClientIP(SOCKET client_socket, char* ipStrResult, char* hostName)
{
	sockaddr_in addr = {};
	socklen_t addr_size = sizeof(sockaddr_in);

	if (getpeername(client_socket, (sockaddr*)&addr, &addr_size))
	{
		addLogMessage("Failed to get client IP", __FILE__, __LINE__);
		return;
	}
	inet_ntop(AF_INET, &addr.sin_addr, ipStrResult, INET_ADDRSTRLEN);

	char servInfo[NI_MAXSERV];
	getnameinfo((sockaddr*)&addr,
		sizeof(sockaddr),
		hostName,
		NI_MAXHOST, servInfo, NI_MAXSERV, NI_NUMERICSERV);
}

void listenForQueries(char* portAtStart, string workingDir)
{
	char port[6]{ '\0' };
	validatePort(port, portAtStart);
	if (!validatePort(port, portAtStart))
		return;

	addrinfo* addr = NULL;

	addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_PASSIVE;

	if (getaddrinfo(NULL, port, &hints, &addr))
	{
		addLogMessage("GetAddrInfo failed", __FILE__, __LINE__);
		return;
	}

	SOCKET listen_socket = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
	if (listen_socket <  0)
	{
		addLogMessage("Error creating listening socket", __FILE__, __LINE__);
		return;
	}

	if (bind(listen_socket, addr->ai_addr, (int)addr->ai_addrlen) < 0)
	{
		addLogMessage("Binding failed", __FILE__, __LINE__);
		return;
	}

	freeaddrinfo(addr);

	if (listen(listen_socket, SOMAXCONN) < 0)
	{
		addLogMessage("Listening failed", __FILE__, __LINE__);
		return;
	}

	while (true)
	{
		SOCKET client_socket = accept(listen_socket, NULL, NULL);
		if (client_socket < 0)
		{
			addLogMessage("Accept failed", __FILE__, __LINE__);
			continue;
		};

		char ipStr[INET_ADDRSTRLEN] { '\0' };
		char hostName[NI_MAXHOST] { '\0' };
		getClientIP(client_socket, ipStr, hostName);
		if (strlen(ipStr))
			addLogMessage((string("Connection accepted from: ") + ipStr + (strlen(hostName) ? (string(", ") + hostName).data() : "")).data());

		char buf[SOCKET_BUFFER_SIZE + 1] { '\0' };
		size_t bytesRead = 0;
		string result = "";

		do
		{
			bytesRead = recv(client_socket, buf, SOCKET_BUFFER_SIZE, 0);
			if (bytesRead > 0)
				result.append(buf, bytesRead);
		} while (bytesRead > 0);

		string decrypted = "";
		if (result.length())
		{
			addLogMessage((string("Message received: ") + result).data());
			decrypted = decrypt(result, workingDir);
			addLogMessage((string("Decrypted message: ") + decrypted).data());
		}

		shutdown(client_socket, SHUT_RDWR);
	};
}

