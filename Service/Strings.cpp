#include <algorithm>
#include <string>
#include <Windows.h>
#include <WinNls.h>

using namespace std;

void rtrim(wstring& s)
{
	s.erase(find_if(s.rbegin(), s.rend(), [](wchar_t ch) {
		return !iswspace(ch);
		}).base(), s.end());
}

void ltrim(wstring& s)
{
	s.erase(s.begin(), find_if(s.begin(), s.end(), [](wchar_t ch) {
		return !iswspace(ch);
		}));
}

void Tolower(wstring& s)
{
	transform(s.begin(), s.end(), s.begin(), towlower);
}

void trim(wstring& s)
{
	ltrim(s);
	rtrim(s);
}

wchar_t* a2w(const char* c, int codePage = CP_UTF8)
{
	int wchars_num = MultiByteToWideChar(codePage, 0, c, -1, NULL, 0);
	wchar_t* wc = new wchar_t[wchars_num];
	MultiByteToWideChar(codePage, 0, c, -1, wc, wchars_num);

	return wc;
}

//char* w2a(const wchar_t* wc, int codePage = CP_UTF8)
//{
//	int chars_num = WideCharToMultiByte(codePage, 0, wc, -1, NULL, 0, NULL, NULL);
//	char* c = new char[chars_num];
//	WideCharToMultiByte(codePage, 0, wc, -1, c, chars_num, NULL, NULL);
//	
//	return c;
//}

LPWSTR GetHomeDirectory()
{
	wchar_t* buffer = new wchar_t[MAX_PATH];
	GetModuleFileName(NULL, (LPTSTR)buffer, MAX_PATH);

	wstring ws = wstring((LPTSTR)buffer);
	size_t pos = ws.find_last_of(L"\\/");
	ws = ws.substr(0, pos);
	wcscpy_s(buffer, ws.length() + 1, ws.data());

	return buffer;
}

void GetTimeAsString(wstring& sTime, SYSTEMTIME* pTime)
{
	sTime = (pTime->wDay < 10 ? L"0" : L"") + to_wstring(pTime->wDay) + L'.' +
		(pTime->wMonth < 10 ? L"0" : L"") + to_wstring(pTime->wMonth) + L'.' +
		to_wstring(pTime->wYear) + L' ' +
		(pTime->wHour < 10 ? L"0" : L"") + to_wstring(pTime->wHour) + L':' +
		(pTime->wMinute < 10 ? L"0" : L"") + to_wstring(pTime->wMinute) + L':' +
		(pTime->wSecond < 10 ? L"0" : L"") + to_wstring(pTime->wSecond);
}

wstring DigitsByGroups(SIZE_T num, wchar_t* separator, size_t digits)
{
	wstring source = to_wstring(num);
	if (source.length() > digits)
	{
		long long beg = source.length() - digits;
		while (beg > 0)
		{
			source.insert(beg, separator);
			beg = beg - digits;
		}
	}
	return source;
}

size_t GetMax(size_t* values, size_t num)
{
	size_t ret = 0;
	for (size_t i = 0; i < num; i++)
		if (values[i] > ret)
			ret = values[i];

	return ret;
}

void RightAlignment(wstring* strings, size_t num)
{
	size_t* lengths = new size_t[num];
	for (int i = 0; i < num; i++)
		lengths[i] = (strings[i].length());

	size_t max = GetMax(lengths, num);

	delete[] lengths;
	
	for (int i = 0; i < num; i++)
	{
		size_t l = strings[i].length();
		if (l != max)
		{
			for (int j = 1; j <= max - l; j++)
				strings[i] = L" " + strings[i];
		}
	}
}