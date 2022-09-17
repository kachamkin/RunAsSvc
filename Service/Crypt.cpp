#include <Windows.h>
#include <tchar.h>
#include <string>
#include "resource.h"

#define BLOCK_SIZE 256
#define MAX_PLAIN_TEXT_BYTES 190
#define AES_KEY_SIZE 32

using namespace std;

BYTE* aesKey;

wchar_t* a2w(const char* c, int codePage = CP_UTF8);

void CryptCleanUp(BYTE** buffers, int numBuffers, BCRYPT_ALG_HANDLE hAlg = NULL, BCRYPT_KEY_HANDLE hKey = NULL, HGLOBAL hResource = NULL, BOOL freeAesKey = FALSE)
{
    if (hAlg)
        BCryptCloseAlgorithmProvider(hAlg, 0);
    if (hKey)
        BCryptDestroyKey(hKey);
    if (freeAesKey)
        free(aesKey);

    for (int i = 0; i < numBuffers; i++)
        free(buffers[i]);

    if (hResource)
    {
        UnlockResource(hResource);
        FreeResource(hResource);
    }
}

void AddBufferToArray(BYTE** bufArray, BYTE* buffer, int* numBuffers)
{
    bufArray[*numBuffers] = buffer;
    (*numBuffers)++;
}

BYTE* CreateBuffer(DWORD size, BYTE** buffers, int* pNumBuffers, BCRYPT_ALG_HANDLE hAlg = NULL, BCRYPT_KEY_HANDLE hKey = NULL)
{
    BYTE* pBuffer = (BYTE*)malloc(size);
    if (!pBuffer)
    {
        CryptCleanUp(buffers, *pNumBuffers, hAlg, hKey);
        return NULL;
    }
    memset(pBuffer, '\0', size);
    AddBufferToArray(buffers, pBuffer, pNumBuffers);
    return pBuffer;
}

//void XOR(wchar_t* source, size_t nSource, wchar_t* key, size_t nKey)
//{
//    size_t j = 0;
//
//    for (size_t i = 0; i < nSource; i++)
//    {
//        *(source + i) = *(source + i) xor *(key + j);
//        if (j == nKey - 1)
//            j = 0;
//        else
//            j++;
//    }
//}

BOOL AesEncrypt(LPWSTR base64str, LPWSTR* b64Result)
{
    *b64Result = new wchar_t[8];
    *b64Result = (LPWSTR)L"Failed!\0";
    
    int numBuffers = 0;
    BYTE* buffers[10] = {};

    BCRYPT_ALG_HANDLE hCryptProv = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;

    ULONG bytesReq = (ULONG)_tcslen(base64str) * sizeof(TCHAR);
    BYTE* pBuffer = (BYTE*)base64str;

    if (FAILED(BCryptOpenAlgorithmProvider(&hCryptProv, BCRYPT_AES_ALGORITHM, NULL, 0)))
    {
        CryptCleanUp(buffers, numBuffers, hCryptProv, NULL, NULL, TRUE);
        return FALSE;
    }

    if (FAILED(BCryptSetProperty(hCryptProv, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0)))
    {
        CryptCleanUp(buffers, numBuffers, hCryptProv, NULL, NULL, TRUE);
        return FALSE;
    }

    ULONG keylen = sizeof(BCRYPT_KEY_DATA_BLOB_HEADER) + AES_KEY_SIZE;
    BYTE* key = CreateBuffer(keylen, buffers, &numBuffers, hCryptProv, hKey);
    if (!key)
    {
        CryptCleanUp(buffers, numBuffers, hCryptProv, NULL, NULL, TRUE);
        return FALSE;
    }

    BCRYPT_KEY_DATA_BLOB_HEADER* header = (BCRYPT_KEY_DATA_BLOB_HEADER*)key;
    header->dwMagic = BCRYPT_KEY_DATA_BLOB_MAGIC;
    header->dwVersion = BCRYPT_KEY_DATA_BLOB_VERSION1;
    header->cbKeyData = AES_KEY_SIZE;
    memcpy(key + sizeof(BCRYPT_KEY_DATA_BLOB_HEADER), aesKey, AES_KEY_SIZE);

    if (FAILED(BCryptImportKey(hCryptProv, NULL, BCRYPT_KEY_DATA_BLOB, &hKey, NULL, NULL, key, keylen, 0)))
    {
        CryptCleanUp(buffers, numBuffers, hCryptProv, NULL, NULL, TRUE);
        return FALSE;
    }

    BYTE* iv = CreateBuffer(AES_KEY_SIZE / 2, buffers, &numBuffers, hCryptProv, hKey);
    if (!iv)
    {
        CryptCleanUp(buffers, numBuffers, hCryptProv, hKey, NULL, TRUE);
        return FALSE;
    }
    memset(iv, '\0', AES_KEY_SIZE / 2);

    ULONG resLen = 0;
    if (FAILED(BCryptEncrypt(hKey, pBuffer, bytesReq, NULL, iv, AES_KEY_SIZE, NULL, 0, &resLen, BCRYPT_BLOCK_PADDING)))
	{
        CryptCleanUp(buffers, numBuffers, hCryptProv, hKey, NULL, TRUE);
		return FALSE;
	}

    BYTE* pResultBuffer = CreateBuffer(resLen, buffers, &numBuffers, hCryptProv, hKey);
    if (!pResultBuffer)
    {
        CryptCleanUp(buffers, numBuffers, hCryptProv, hKey, NULL, TRUE);
        return FALSE;
    }
    memset(pResultBuffer, '\0', resLen);

    if (FAILED(BCryptEncrypt(hKey, pBuffer, bytesReq, NULL, iv, AES_KEY_SIZE, pResultBuffer, resLen, &resLen, BCRYPT_BLOCK_PADDING)))
    {
        CryptCleanUp(buffers, numBuffers, hCryptProv, hKey, NULL, TRUE);
        return FALSE;
    }

    DWORD b64Length = 0;
    if (!CryptBinaryToString(pResultBuffer, resLen, CRYPT_STRING_BASE64, NULL, &b64Length))
    {
        CryptCleanUp(buffers, numBuffers, hCryptProv, hKey, NULL, TRUE);
        return FALSE;
    }

    *b64Result = new wchar_t[b64Length + 1];
    if (!CryptBinaryToString(pResultBuffer, resLen, CRYPT_STRING_BASE64, *b64Result, &b64Length))
    {
        CryptCleanUp(buffers, numBuffers, hCryptProv, hKey, NULL, TRUE);
        return FALSE;
    }
    (*b64Result)[b64Length] = L'\0';

    CryptCleanUp(buffers, numBuffers, hCryptProv, hKey, NULL, TRUE);

    return TRUE;
}

BOOL AesDecrypt(LPWSTR base64str, BYTE* pBuffer, ULONG bytesReq)
{
    int numBuffers = 0;
    BYTE* buffers[10] = {};

    BCRYPT_ALG_HANDLE hCryptProv = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;

    if (FAILED(BCryptOpenAlgorithmProvider(&hCryptProv, BCRYPT_AES_ALGORITHM, NULL, 0)))
        return FALSE;

    if (FAILED(BCryptSetProperty(hCryptProv, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0)))
        return FALSE;

    ULONG keylen = sizeof(BCRYPT_KEY_DATA_BLOB_HEADER) + AES_KEY_SIZE;
    BYTE* key = CreateBuffer(keylen, buffers, &numBuffers, hCryptProv, hKey);
    if (!key)
    {
        CryptCleanUp(buffers, numBuffers, hCryptProv, NULL, NULL);
        return FALSE;
    }

    BCRYPT_KEY_DATA_BLOB_HEADER* header = (BCRYPT_KEY_DATA_BLOB_HEADER*)key;
    header->dwMagic = BCRYPT_KEY_DATA_BLOB_MAGIC;
    header->dwVersion = BCRYPT_KEY_DATA_BLOB_VERSION1;
    header->cbKeyData = AES_KEY_SIZE;
    memcpy(key + sizeof(BCRYPT_KEY_DATA_BLOB_HEADER), aesKey, AES_KEY_SIZE);

    if (FAILED(BCryptImportKey(hCryptProv, NULL, BCRYPT_KEY_DATA_BLOB, &hKey, NULL, NULL, key, keylen, 0)))
    {
        CryptCleanUp(buffers, numBuffers, hCryptProv, NULL, NULL);
        return FALSE;
    }

    BYTE* iv = CreateBuffer(AES_KEY_SIZE / 2, buffers, &numBuffers, hCryptProv, hKey);
    if (!iv)
    {
        CryptCleanUp(buffers, numBuffers, hCryptProv, hKey, NULL);
        return FALSE;
    }
    memset(iv, '\0', AES_KEY_SIZE / 2);

    ULONG resLen = 0;
    if (FAILED(BCryptDecrypt(hKey, pBuffer, bytesReq, NULL, iv, AES_KEY_SIZE, NULL, 0, &resLen, BCRYPT_BLOCK_PADDING)))
    {
        CryptCleanUp(buffers, numBuffers, hCryptProv, hKey, NULL);
        return FALSE;
    }

    BYTE* pResultBuffer = CreateBuffer(resLen + 1, buffers, &numBuffers, hCryptProv, hKey);
    if (!pResultBuffer)
    {
        CryptCleanUp(buffers, numBuffers, hCryptProv, hKey, NULL);
        return FALSE;
    }
    memset(pResultBuffer, '\0', resLen + 1);

    if (FAILED(BCryptDecrypt(hKey, pBuffer, bytesReq, NULL, iv, AES_KEY_SIZE, pResultBuffer, resLen, &resLen, BCRYPT_BLOCK_PADDING)))
    {
        CryptCleanUp(buffers, numBuffers, hCryptProv, hKey, NULL);
        return FALSE;
    }

    LPTSTR pBufStr = a2w((char*)pResultBuffer);
    _tcscpy_s(base64str, _tcslen(pBufStr) + 1, pBufStr);
    delete[] pBufStr;

    CryptCleanUp(buffers, numBuffers, hCryptProv, hKey, NULL);

    free(pBuffer);
    return TRUE;
}

BOOL Decrypt(LPTSTR base64str)
{
    aesKey = (BYTE*)malloc(AES_KEY_SIZE);
    if (!aesKey)
        return FALSE;

    int numBuffers = 0;
    BYTE* buffers[10] = {};

    BCRYPT_ALG_HANDLE hCryptProv = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;

    DWORD bytesReq = 0;
    if (!CryptStringToBinary(base64str, NULL, CRYPT_STRING_BASE64, NULL, &bytesReq, NULL, NULL))
        return FALSE;

    BYTE* pBuffer = CreateBuffer(bytesReq, buffers, &numBuffers, hCryptProv, hKey);
    if (!pBuffer)
        return FALSE;

    if (!CryptStringToBinary(base64str, NULL, CRYPT_STRING_BASE64, pBuffer, &bytesReq, NULL, NULL))
    {
        CryptCleanUp(buffers, numBuffers);
        return FALSE;
    }

    if (bytesReq <= BLOCK_SIZE)
    {
        CryptCleanUp(buffers, numBuffers);
        return FALSE;
    }

    HRSRC hRsc = FindResource(NULL, MAKEINTRESOURCE(IDR_KEY1), L"Key");
    if (!hRsc)
    {
        CryptCleanUp(buffers, numBuffers);
        return FALSE;
    }

    HGLOBAL hGlobal = LoadResource(NULL, hRsc);
    if (!hGlobal)
    {
        CryptCleanUp(buffers, numBuffers);
        return FALSE;
    }

    BYTE* pKey = (BYTE*)LockResource(hGlobal);
    if (!pKey)
    {
        CryptCleanUp(buffers, numBuffers, NULL, NULL, hGlobal);
        return FALSE;
    }

    DWORD bytesReqKey = SizeofResource(NULL, hRsc);
    if (!bytesReqKey)
    {
        CryptCleanUp(buffers, numBuffers, NULL, NULL, hGlobal);
        return FALSE;
    }

    DWORD keyBlobLength = 0;
    if (!CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, PKCS_RSA_PRIVATE_KEY,
        pKey,
        bytesReqKey, CRYPT_DECODE_NOCOPY_FLAG, NULL, NULL, &keyBlobLength))
    {
        CryptCleanUp(buffers, numBuffers);
        return FALSE;
    }

    BYTE* keyBlob = CreateBuffer(keyBlobLength, buffers, &numBuffers, hCryptProv, hKey);
    if (!keyBlob)
        return FALSE;

    if (!CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, PKCS_RSA_PRIVATE_KEY,
        pKey,
        bytesReqKey, CRYPT_DECODE_NOCOPY_FLAG, NULL, keyBlob, &keyBlobLength))
    {
        CryptCleanUp(buffers, numBuffers, NULL, NULL, hGlobal);
        return FALSE;
    }

    if (FAILED(BCryptOpenAlgorithmProvider(
        &hCryptProv,
        BCRYPT_RSA_ALGORITHM, NULL,
        0)))
    {
        CryptCleanUp(buffers, numBuffers, NULL, NULL, hGlobal);
        return FALSE;
    }

    ULONG keySize = 0;
    if (FAILED(BCryptImportKeyPair(hCryptProv, NULL, LEGACY_RSAPRIVATE_BLOB, &hKey, keyBlob, keyBlobLength, BCRYPT_NO_KEY_VALIDATION)))
    {
        CryptCleanUp(buffers, numBuffers, hCryptProv, NULL, hGlobal);
        return FALSE;
    }

    BCRYPT_OAEP_PADDING_INFO pi = { 0 };
    pi.pszAlgId = BCRYPT_SHA256_ALGORITHM;

    DWORD blockSize = BLOCK_SIZE; //for 2048-bit RSA key
    DWORD maxDataLen = MAX_PLAIN_TEXT_BYTES; //for 2048-bit RSA key and SHABLOCK_SIZE OAEP: KeySize - 2 * hashSize / 8 - 2 (sizes in bytes)

    BYTE* pMaxLenBuffer = CreateBuffer(blockSize, buffers, &numBuffers, hCryptProv, hKey);
    if (!pMaxLenBuffer)
    {
        CryptCleanUp(buffers, numBuffers, hCryptProv, NULL, hGlobal);
        return FALSE;
    }
    memcpy(pMaxLenBuffer, pBuffer, blockSize);


    BYTE* pbRes = CreateBuffer(maxDataLen, buffers, &numBuffers, hCryptProv, hKey);
    if (!pbRes)
    {
        CryptCleanUp(buffers, numBuffers, hCryptProv, hKey, hGlobal);
        return FALSE;
    }
    memset(pbRes, '\0', maxDataLen);

	if (FAILED(BCryptDecrypt(
		hKey, pMaxLenBuffer, blockSize, &pi, NULL, 0, pbRes, maxDataLen, &maxDataLen, BCRYPT_PAD_OAEP)))
	{
		CryptCleanUp(buffers, numBuffers, hCryptProv, hKey, hGlobal);
		return FALSE;
	}
    memcpy(aesKey, pbRes, AES_KEY_SIZE);

    BYTE* pbResult = (BYTE*)malloc(bytesReq - blockSize);
    if (!pbResult)
    {
        CryptCleanUp(buffers, numBuffers, hCryptProv, hKey, hGlobal);
        return FALSE;
    }
    memcpy(pbResult, pBuffer + blockSize, bytesReq - blockSize);

    CryptCleanUp(buffers, numBuffers, hCryptProv, hKey, hGlobal);

    return AesDecrypt(base64str, pbResult, bytesReq - blockSize);
}

//BOOL Encrypt(LPWSTR base64str, LPWSTR* b64Result)
//{
//    int numBuffers = 0;
//    BYTE* buffers[10] = {};
//
//    BCRYPT_ALG_HANDLE hCryptProv = NULL;
//    BCRYPT_KEY_HANDLE hKey = NULL;
//
//    DWORD bytesReq = _tcslen(base64str) * sizeof(TCHAR);
//    BYTE* pBuffer = (BYTE*)base64str;
//
//    HRSRC hRsc = FindResource(NULL, MAKEINTRESOURCE(IDR_KEY1), L"Key");
//    if (!hRsc)
//    {
//        CryptCleanUp(buffers, numBuffers);
//        return FALSE;
//    }
//
//    HGLOBAL hGlobal = LoadResource(NULL, hRsc);
//    if (!hGlobal)
//    {
//        CryptCleanUp(buffers, numBuffers);
//        return FALSE;
//    }
//
//    BYTE* pKey = (BYTE*)LockResource(hGlobal);
//    if (!pKey)
//    {
//        CryptCleanUp(buffers, numBuffers, NULL, NULL, hGlobal);
//        return FALSE;
//    }
//
//    DWORD bytesReqKey = SizeofResource(NULL, hRsc);
//    if (!bytesReqKey)
//    {
//        CryptCleanUp(buffers, numBuffers, NULL, NULL, hGlobal);
//        return FALSE;
//    }
//
//    DWORD keyBlobLength = 0;
//    if (!CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, PKCS_RSA_PRIVATE_KEY,
//        pKey,
//        bytesReqKey, CRYPT_DECODE_NOCOPY_FLAG, NULL, NULL, &keyBlobLength))
//    {
//        CryptCleanUp(buffers, numBuffers, NULL, NULL, hGlobal);
//        return FALSE;
//    }
//
//    BYTE* keyBlob = CreateBuffer(keyBlobLength, buffers, &numBuffers, hCryptProv, hKey);
//    if (!keyBlob)
//        return FALSE;
//
//    if (!CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, PKCS_RSA_PRIVATE_KEY,
//        pKey,
//        bytesReqKey, CRYPT_DECODE_NOCOPY_FLAG, NULL, keyBlob, &keyBlobLength))
//    {
//        CryptCleanUp(buffers, numBuffers, NULL, NULL, hGlobal);
//        return FALSE;
//    }
//
//    if (FAILED(BCryptOpenAlgorithmProvider(
//        &hCryptProv,
//        BCRYPT_RSA_ALGORITHM, NULL,
//        0)))
//    {
//        CryptCleanUp(buffers, numBuffers, NULL, NULL, hGlobal);
//        return FALSE;
//    }
//
//    ULONG keySize = 0;
//    if (FAILED(BCryptImportKeyPair(hCryptProv, NULL, LEGACY_RSAPRIVATE_BLOB, &hKey, keyBlob, keyBlobLength, BCRYPT_NO_KEY_VALIDATION)))
//    {
//        CryptCleanUp(buffers, numBuffers, hCryptProv, NULL, hGlobal);
//        return FALSE;
//    }
//
//    BCRYPT_OAEP_PADDING_INFO pi = { 0 };
//    pi.pszAlgId = BCRYPT_SHA256_ALGORITHM;
//
//    //Decryption by blocks if plain text length is more than maxDataLen
//
//    DWORD blockSize = BLOCK_SIZE; //for 2048-bit RSA key
//    DWORD maxDataLen = MAX_PLAIN_TEXT_BYTES; //for 2048-bit RSA key and SHABLOCK_SIZE OAEP: KeySize - 2 * hashSize / 8 - 2 (sizes in bytes)
//
//    BYTE* pMaxLenBuffer = CreateBuffer(maxDataLen, buffers, &numBuffers, hCryptProv, hKey);
//    if (!pMaxLenBuffer)
//        return FALSE;
//
//    unsigned int blockNum = bytesReq / maxDataLen;
//    if (bytesReq % maxDataLen)
//        blockNum++;
//
//    unsigned long resLen = blockNum * blockSize;
//    BYTE* pResultBuffer = CreateBuffer(resLen, buffers, &numBuffers, hCryptProv, hKey);
//    if (!pResultBuffer)
//        return FALSE;
//
//    BYTE* pbRes = CreateBuffer(blockSize, buffers, &numBuffers, hCryptProv, hKey);
//    if (!pbRes)
//        return FALSE;
//
//    for (unsigned int i = 0; i < blockNum; i++)
//    {
//        memcpy(pMaxLenBuffer, pBuffer + i * maxDataLen, maxDataLen);
//        memset(pbRes, '\0', blockSize);
//
//        if (FAILED(BCryptEncrypt(
//            hKey, pMaxLenBuffer, maxDataLen, &pi, NULL, 0, pbRes, blockSize, &blockSize, BCRYPT_PAD_OAEP)))
//        {
//            CryptCleanUp(buffers, numBuffers, hCryptProv, hKey, hGlobal);
//            return FALSE;
//        }
//
//        memcpy(pResultBuffer + i * blockSize, pbRes, blockSize);
//    }
//
//    DWORD b64Length = 0;
//    if (!CryptBinaryToString(pResultBuffer, resLen, CRYPT_STRING_BASE64, NULL, &b64Length))
//    {
//        CryptCleanUp(buffers, numBuffers, hCryptProv, hKey, hGlobal);
//        return FALSE;
//    }
//
//    *b64Result = new wchar_t[b64Length + 1];
//    if (!CryptBinaryToString(pResultBuffer, resLen, CRYPT_STRING_BASE64, *b64Result, &b64Length))
//    {
//        CryptCleanUp(buffers, numBuffers, hCryptProv, hKey, hGlobal);
//        return FALSE;
//    }
//    (*b64Result)[b64Length] = L'\0';
//
//    CryptCleanUp(buffers, numBuffers, hCryptProv, hKey, hGlobal);
//
//    return TRUE;
//}