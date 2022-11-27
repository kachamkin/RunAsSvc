#pragma once

#include <cstdio>
#include <cstdlib>
#include <syslog.h>
#include <string.h>
#include <string>
#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/aes.h>

#define SERVICE_NAME "Run As Service"
#define DEFAULT_PORT "500"
#define RSA_BLOCK_SIZE 256
#define AES_KEY_SIZE 32
#define SOCKET_BUFFER_SIZE 2048
#define SOCKET int

using namespace std;

void addLogMessage(const char* message, const char* file = NULL, int line = 0);
bool validatePort(char* port, char* arg);
void listenForQueries(char* portAtStart, string workingDir);
string base64_encode(unsigned char const* bytes_to_encode, unsigned int in_len);
string base64_decode(string const& encoded_string);
string decrypt(string rawData, string workingDir);