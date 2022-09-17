#include <string>
#include <Windows.h>
#include <Shlwapi.h>

using namespace std;

PBITMAPINFO CreateBitmapInfoStruct(HBITMAP hBmp)
{
    BITMAP bmp{};
    PBITMAPINFO pbmi;
    WORD    cClrBits;

    if (!GetObject(hBmp, sizeof(BITMAP), (LPSTR)&bmp))
        return NULL;

    cClrBits = bmp.bmPlanes * bmp.bmBitsPixel;
    if (cClrBits == 1)
        cClrBits = 1;
    else if (cClrBits <= 4)
        cClrBits = 4;
    else if (cClrBits <= 8)
        cClrBits = 8;
    else if (cClrBits <= 16)
        cClrBits = 16;
    else if (cClrBits <= 24)
        cClrBits = 24;
    else cClrBits = 32;

	pbmi = cClrBits < 24 ? (PBITMAPINFO)malloc(sizeof(BITMAPINFOHEADER) + sizeof(RGBQUAD) * (static_cast<unsigned long long>(1) << cClrBits)) :
		(PBITMAPINFO)malloc(sizeof(BITMAPINFOHEADER));
    if (!pbmi)
        return NULL;

    pbmi->bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    pbmi->bmiHeader.biWidth = bmp.bmWidth;
    pbmi->bmiHeader.biHeight = bmp.bmHeight;
    pbmi->bmiHeader.biPlanes = bmp.bmPlanes;
    pbmi->bmiHeader.biBitCount = bmp.bmBitsPixel;
    if (cClrBits < 24)
        pbmi->bmiHeader.biClrUsed = (1 << cClrBits);

    pbmi->bmiHeader.biCompression = BI_RGB;

    pbmi->bmiHeader.biSizeImage = ((pbmi->bmiHeader.biWidth * cClrBits + 31) & ~31) / 8 * pbmi->bmiHeader.biHeight;
    pbmi->bmiHeader.biClrImportant = 0;
    return pbmi;
}

void CreateBMPFile(PBITMAPINFO pbi, HBITMAP hBMP, wstring* output)
{
    *output = L"";
    
    if (!pbi)
        return;
    
    BITMAPFILEHEADER hdr{};        
    PBITMAPINFOHEADER pbih;       
    LPBYTE lpBits;                
    
    pbih = (PBITMAPINFOHEADER)pbi;
    lpBits = (LPBYTE)malloc(pbih->biSizeImage);
    if (!lpBits)
        return;

    HDC hDC = CreateDC(L"DISPLAY", NULL, NULL, NULL);
    if (!hDC)
        return;
    
    if (!GetDIBits(hDC, hBMP, 0, (WORD)pbih->biHeight, lpBits, pbi, DIB_RGB_COLORS))
        return;

    hdr.bfType = 0x4d42;        // 0x42 = "B" 0x4d = "M"  
    hdr.bfSize = (DWORD)(sizeof(BITMAPFILEHEADER) +
        pbih->biSize + pbih->biClrUsed
        * sizeof(RGBQUAD) + pbih->biSizeImage);
    hdr.bfReserved1 = 0;
    hdr.bfReserved2 = 0;

    hdr.bfOffBits = (DWORD)sizeof(BITMAPFILEHEADER) +
        pbih->biSize + pbih->biClrUsed
        * sizeof(RGBQUAD);

    DWORD total = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER) + pbih->biClrUsed * sizeof(RGBQUAD) + pbih->biSizeImage;
    BYTE* pbResult = (BYTE*)malloc(total);
    if (!pbResult)
        return;

    memcpy(pbResult, &hdr, sizeof(BITMAPFILEHEADER));
    memcpy(pbResult + sizeof(BITMAPFILEHEADER), pbih, sizeof(BITMAPINFOHEADER) + pbih->biClrUsed * sizeof(RGBQUAD));
    memcpy(pbResult + sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER) + pbih->biClrUsed * sizeof(RGBQUAD), lpBits, pbih->biSizeImage);

    DWORD b64Length = 0;
    if (!CryptBinaryToString(pbResult, total, CRYPT_STRING_BASE64, NULL, &b64Length))
    {
        free(pbResult);
        LocalFree(pbi);
        GlobalFree((HGLOBAL)lpBits);
    }

    wchar_t* b64Result = new wchar_t[b64Length]{L'\0'};
    if (!CryptBinaryToString(pbResult, total, CRYPT_STRING_BASE64, b64Result, &b64Length))
    {
        free(pbResult);
        LocalFree(pbi);
        GlobalFree((HGLOBAL)lpBits);
        delete[] b64Result;
    }

    output->append(b64Result);

    free(pbResult);
    free(pbi);
    free(lpBits);
    delete[] b64Result;
}

void CreateBMP(LPWSTR fileName, wstring* output)
{
    SHFILEINFO fi{};
    if (SHGetFileInfo(fileName, 0, &fi, sizeof(SHFILEINFO), SHGFI_ICON | SHGFI_SMALLICON | SHGFI_USEFILEATTRIBUTES))
    {
        ICONINFO ii{};
        if (fi.hIcon && GetIconInfo(fi.hIcon, &ii))
        {
            if (ii.hbmColor)
            {
                PBITMAPINFO pbi = CreateBitmapInfoStruct(ii.hbmColor);
                CreateBMPFile(pbi, ii.hbmColor, output);
            }
            DestroyIcon(fi.hIcon);
        }
    }
}