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

int aesDecrypt(unsigned char* ciphertext, int ciphertext_len, unsigned char* key, unsigned char* plaintext)
{
	EVP_CIPHER_CTX* ctx = NULL;
	int len = 0, plaintext_len = 0, ret;

	unsigned char iv[AES_BLOCK_SIZE / 2]{ 0 };

	if (!(ctx = EVP_CIPHER_CTX_new())) 
	{
		addLogMessage("Failed to create AES context", __FILE__, __LINE__);
		return -1;
	}

	if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, NULL, NULL))
	{
		addLogMessage("Failed to initialize AES", __FILE__, __LINE__);
		return -1;
	}

	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_KEY_SIZE / 2, NULL))
	{
		addLogMessage("Failed to initialize IV", __FILE__, __LINE__);
		return -1;
	}

	if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
	{
		addLogMessage("Failed to set IV", __FILE__, __LINE__);
		return -1;
	}
	
	if (!EVP_CIPHER_CTX_set_padding(ctx, 0))
	{
		addLogMessage("Failed to disable padding", __FILE__, __LINE__);
		return -1;
	}


	if (ciphertext)
	{
		if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
		{
			addLogMessage("Failed to AES decrypt", __FILE__, __LINE__);
			return -1;
		}

		plaintext_len = len;
	}

	ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

	EVP_CIPHER_CTX_free(ctx);

	if (ret)
	{
		plaintext_len += len;
		return plaintext_len;
	}
	else
		return -1;
}

int aesEncrypt(unsigned char* plaintext, int plaintext_len, unsigned char* key, unsigned char* ciphertext)
{
	EVP_CIPHER_CTX* ctx = NULL;
	int len = 0, ciphertext_len = 0;

	unsigned char iv[AES_BLOCK_SIZE / 2]{ 0 };

	if (!(ctx = EVP_CIPHER_CTX_new()))
	{
		addLogMessage("Failed to create AES context", __FILE__, __LINE__);
		return -1;
	}

	if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, NULL, NULL))
	{
		addLogMessage("Failed to initialize AES", __FILE__, __LINE__);
		return -1;
	}

	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_KEY_SIZE / 2, NULL))
	{
		addLogMessage("Failed to initialize IV", __FILE__, __LINE__);
		return -1;
	}

	if (!EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) 
	{
		addLogMessage("Failed to set IV", __FILE__, __LINE__);
		return -1;
	}

	if (plaintext)
	{
		if (!EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
		{
			addLogMessage("Failed to AES encrypt", __FILE__, __LINE__);
			return -1;
		}

		ciphertext_len = len;
	}

	if (!EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
	{
		addLogMessage("Failed to finalize AES encrypt", __FILE__, __LINE__);
		return -1;
	}

	ciphertext_len += len;

	EVP_CIPHER_CTX_free(ctx);

	return ciphertext_len;
}

string decrypt(string rawData, string workingDir, unsigned char* aesKey)
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

	unsigned char data[RSA_BLOCK_SIZE]{};
	memcpy(data, decoded.substr(0, RSA_BLOCK_SIZE).data(), RSA_BLOCK_SIZE);

	if (RSA_private_decrypt(RSA_BLOCK_SIZE, data, aesKey, rsa, RSA_PKCS1_PADDING) < 0)
	{
		addLogMessage("Failed to decrypt AES key", __FILE__, __LINE__);
		RSA_free(rsa);
		return "";
	}
	
	RSA_free(rsa);

	unsigned char toAes[decoded.length() - RSA_BLOCK_SIZE];
	return aesDecrypt((unsigned char*)decoded.substr(RSA_BLOCK_SIZE).data(), decoded.length() - RSA_BLOCK_SIZE, aesKey, toAes) > 0 ? (char*)toAes : "";
}