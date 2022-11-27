#include "header.h"

inline RSA* getRSAfromFile(string workingDir)
{
	FILE* privKey = fopen((workingDir + "/private.key").data(), "rb");
	if (!privKey)
	{
		addLogMessage("Failed to open private key file", __FILE__, __LINE__);
		return NULL;
	}

	RSA* rsa = RSA_new();
	PEM_read_RSAPrivateKey(privKey, &rsa, NULL, NULL);
	if (!rsa)
	{
		addLogMessage("Failed to read RSA private key", __FILE__, __LINE__);
		fclose(privKey);
		return NULL;
	}

	fclose(privKey);
	return rsa;
}

inline string aesDecrypt(unsigned char* key, unsigned char* data, size_t cb)
{
	unsigned char buffer[cb];

	AES_KEY aesKey{};
	AES_set_decrypt_key(key, AES_KEY_SIZE * 8, &aesKey);
	AES_decrypt(data, buffer, &aesKey);

	return (char*)buffer;
}

string decrypt(string rawData, string workingDir)
{
	RSA* rsa = getRSAfromFile(workingDir);

	string decoded = "";
	try
	{
		decoded = base64_decode(rawData);
	}
	catch (...)
	{
		addLogMessage("Failed to decode base64 data", __FILE__, __LINE__);
		RSA_free(rsa);
		return "";
	}

	unsigned char aesKey[AES_KEY_SIZE]{};
	unsigned char data[RSA_BLOCK_SIZE]{};
	memcpy(data, decoded.substr(0, RSA_BLOCK_SIZE).data(), RSA_BLOCK_SIZE);

	int res = RSA_private_decrypt(RSA_BLOCK_SIZE, data, aesKey, rsa, RSA_PKCS1_PADDING);
	if (res == - 1)
	{
		addLogMessage("Failed to decrypt AES key", __FILE__, __LINE__);
		RSA_free(rsa);
		return "";
	}
	
	RSA_free(rsa);

	return aesDecrypt(aesKey, (unsigned char*)decoded.substr(RSA_BLOCK_SIZE).data(), decoded.length() - RSA_BLOCK_SIZE);
}