#include <WinSock2.h>
#include <string>
#include <WtsApi32.h>
#include <tchar.h>
#include <tlhelp32.h>
#include <Psapi.h>
#include <unordered_map>
#include <powerbase.h>
#include <strsafe.h>
//#include <dbghelp.h>

#define MAX_THREADS_PER_PROCESS 2048
#define MAX_FILE_BUFFER_SIZE 1048576

using namespace std;

typedef struct _PROCESSOR_POWER_INFORMATION { ULONG  Number;  ULONG  MaxMhz;  ULONG  CurrentMhz;  ULONG  MhzLimit;  ULONG  MaxIdleState;  ULONG  CurrentIdleState; } PROCESSOR_POWER_INFORMATION, * PPROCESSOR_POWER_INFORMATION;
typedef struct _FINFO { wstring product; wstring company; wstring image; } FINFO;

BOOL execResult = TRUE;
wstring processList;
unordered_map<wstring, FINFO> fInfo;

wchar_t* a2w(const char* c, int codePage = CP_UTF8);
void rtrim(wstring& s);
void ltrim(wstring& s);
void trim(wstring& s);
void Tolower(wstring& s);
void GetTimeAsString(wstring& sTime, SYSTEMTIME* pTime);
wstring DigitsByGroups(SIZE_T num, wchar_t* separator, size_t digits);
void RightAlignment(wstring* strings, size_t num);
void CreateBMP(LPWSTR fileName, wstring* output);

wstring GetSystemNameAndVersion();
void GetDevices(wstring className);
void ExecMethod(wstring className, wstring methodName, wstring& filter);

void addLogMessage(const TCHAR* a);
BOOL Decrypt(LPTSTR base64str);

//void GetStack(HANDLE process, HANDLE thread, wstring* output)
//{
//	*output = L"";
//	
//	STACKFRAME stack{0};
//	wchar_t name[256]{L'\0'};
//
//	SYMBOL_INFOW* pSymbol = (SYMBOL_INFOW*)calloc(sizeof(SYMBOL_INFOW) + 256 * sizeof(wchar_t), 1);
//	if (!pSymbol)
//		return;
//
//	pSymbol->MaxNameLen = 255;
//	pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
//
//	CONTEXT context{};
//	RtlCaptureContext(&context);
//
//	SymInitializeW(process, L"C:\\ProgramData\\dbg\\sym", TRUE);
//
//	DWORD64 displacement = 0;
//	stack.AddrPC.Offset = context.Rip;
//	stack.AddrPC.Mode = AddrModeFlat;
//	stack.AddrStack.Offset = context.Rsp;
//	stack.AddrStack.Mode = AddrModeFlat;
//	stack.AddrFrame.Offset = context.Rbp;
//	stack.AddrFrame.Mode = AddrModeFlat;
//
//	for (ULONG frame = 0; ; frame++)
//	{
//		if (!StackWalk64(IMAGE_FILE_MACHINE_AMD64, process, thread, &stack, &context, NULL, SymFunctionTableAccess64, SymGetModuleBase64, NULL))
//			break;
//
//		if (SymFromAddrW(process, (ULONG64)stack.AddrPC.Offset, &displacement, pSymbol))
//		{
//			UnDecorateSymbolNameW(pSymbol->Name, (PWSTR)name, 256, UNDNAME_COMPLETE);
//			output->append(L"Name: " + wstring(pSymbol->Name) + wstring(L";"));
//			output->append(L"Address: " + to_wstring(pSymbol->Address) + L";");
//			output->append(L"Module base: " + to_wstring(pSymbol->ModBase) + L";");
//		}
//		else
//		{
//			output->append(L"Offset: " + to_wstring(stack.AddrPC.Offset) + L";");
//			output->append(L"Segment: " + to_wstring(stack.AddrPC.Segment) + L";");
//		}
//	}
//
//	free(pSymbol);
//	SymCleanup(process);
//}

void GetFileSystemTree(wstring entry, wstring* output)
{
	*output = L"";
	
	if (entry.empty())
	{
		wchar_t volName[MAX_PATH];
		HANDLE h = FindFirstVolume(volName, MAX_PATH);
		if (h != INVALID_HANDLE_VALUE)
		{
			do
			{
				DWORD  CharCount = MAX_PATH + 1;
				PWCHAR Names = NULL;
				PWCHAR NameIdx = NULL;

				Names = (PWCHAR) new BYTE[CharCount * sizeof(WCHAR)];

				if (GetVolumePathNamesForVolumeName(volName, Names, CharCount, &CharCount))
				{
					for (NameIdx = Names; NameIdx[0] != L'\0'; NameIdx += wcslen(NameIdx) + 1)
					{
						output->append(wstring(NameIdx) + L";;");
						output->append(L"1;");

						ULARGE_INTEGER total{}, free{};
						if (GetDiskFreeSpaceEx(NameIdx, NULL, &total, &free))
						{
							output->append(DigitsByGroups(total.QuadPart / 1073741824, (wchar_t*)L" ", 3) + L" GB;");
							output->append(DigitsByGroups(free.QuadPart / 1073741824, (wchar_t*)L" ", 3) + L" GB;");
						}
						else
							output->append(L";;");

						output->append(L"\r\n");
					}
				}
			} while (FindNextVolume(h, volName, MAX_PATH));
		}
		FindVolumeClose(h);
	}
	else
	{
		WIN32_FIND_DATA fd{};
		wstring quotes = entry;
		quotes = quotes.append(quotes[quotes.length() - 1] == L'\\' ? L"*" : L"\\*");

		HANDLE h = FindFirstFile(quotes.data(), &fd);
		if (h != INVALID_HANDLE_VALUE)
		{
			do
			{
				wstring fileName = entry + (entry[entry.length() - 1] == L'\\' ? L"" : L"\\") + wstring(fd.cFileName);
				
				output->append(wstring(fd.cFileName) + L";");
				output->append(fileName + L";");
				output->append(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY ? L"1;" : L"0;");

				HANDLE hFile = CreateFile(fileName.data(), GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
				
				LARGE_INTEGER size{};
				if (GetFileSizeEx(hFile, &size))
				{
					if (size.QuadPart < 1024)
						output->append(DigitsByGroups(size.QuadPart, (wchar_t*)L" ", 3) + L" B;");
					else if (size.QuadPart < 1048576)
						output->append(DigitsByGroups(size.QuadPart / 1024, (wchar_t*)L" ", 3) + L" K;");
					else if (size.QuadPart < 1073741824)
						output->append(DigitsByGroups(size.QuadPart / 1048576, (wchar_t*)L" ", 3) + L" M;");
					else
						output->append(DigitsByGroups(size.QuadPart / 1073741824, (wchar_t*)L" ", 3) + L" G;");
				}
				else
					output->append(L";");

				FILETIME ftLastModified{};
				SYSTEMTIME stLastModified{}, ltLastModified{};
				wstring sTime = L"";
				if (GetFileTime(hFile, NULL, NULL, &ftLastModified))
					if (FileTimeToSystemTime(&ftLastModified, &stLastModified))
					{
						TIME_ZONE_INFORMATION tz{};
						if (GetTimeZoneInformation(&tz) != TIME_ZONE_ID_INVALID)
							if (SystemTimeToTzSpecificLocalTime(&tz, &stLastModified, &ltLastModified))
								GetTimeAsString(sTime, &ltLastModified);
							else
								output->append(L";");
						else
							output->append(L";");
					}
					else
						output->append(L";");
				else
					output->append(L";");

				CloseHandle(hFile);

				output->append(sTime);
				output->append(L"\r\n");

			} while (FindNextFile(h, &fd));
		}
		else
			output->append(L" ");
		FindClose(h);
	}
}

void GetFileInfo(LPWSTR fileName, wstring* product, wstring* company, wstring* version = NULL, wstring* descr = NULL)
{
	*product = L"";
	*company = L"";
	if (version)
		*version = L"";
	if (descr)
		*descr = L"";

	DWORD handle = NULL;
	DWORD dwLen = GetFileVersionInfoSize(fileName, &handle);
	if (!dwLen)
		return;

	BYTE* pBlock = (BYTE*)malloc(dwLen);
	if (!pBlock)
		return;

	if (!GetFileVersionInfo(fileName, handle, dwLen, pBlock))
	{
		free(pBlock);
		return;
	}
	
	struct LANGANDCODEPAGE
	{
		WORD wLanguage;
		WORD wCodePage;
	} *lpTranslate = NULL;

	UINT cbTranslate = 0;
	if (!VerQueryValue(pBlock, L"\\VarFileInfo\\Translation", (LPVOID*)&lpTranslate, &cbTranslate))
	{
		free(pBlock);
		return;
	}

	if (!cbTranslate)
	{
		free(pBlock);
		return;
	}

	wchar_t* pBuffer = NULL;
	UINT dwBytes = 0;
	wchar_t SubBlock[1024]{ L'\0' };

	if (FAILED(StringCchPrintf(SubBlock, 50, L"\\StringFileInfo\\%04x%04x\\ProductName", lpTranslate[0].wLanguage, lpTranslate[0].wCodePage)))
	{
		free(pBlock);
		return;
	}
	if (VerQueryValue(pBlock, SubBlock, (LPVOID*)&pBuffer, &dwBytes))
		product->append(pBuffer);

	if (FAILED(StringCchPrintf(SubBlock, 50, L"\\StringFileInfo\\%04x%04x\\CompanyName", lpTranslate[0].wLanguage, lpTranslate[0].wCodePage)))
	{
		free(pBlock);
		return;
	}
	if (VerQueryValue(pBlock, SubBlock, (LPVOID*)&pBuffer, &dwBytes))
		company->append(pBuffer);

	if (version)
	{
		if (FAILED(StringCchPrintf(SubBlock, 50, L"\\StringFileInfo\\%04x%04x\\FileVersion", lpTranslate[0].wLanguage, lpTranslate[0].wCodePage)))
		{
			free(pBlock);
			return;
		}
		if (VerQueryValue(pBlock, SubBlock, (LPVOID*)&pBuffer, &dwBytes))
			version->append(pBuffer);
	}

	if (descr)
	{
		if (FAILED(StringCchPrintf(SubBlock, 50, L"\\StringFileInfo\\%04x%04x\\FileDescription", lpTranslate[0].wLanguage, lpTranslate[0].wCodePage)))
		{
			free(pBlock);
			return;
		}
		if (VerQueryValue(pBlock, SubBlock, (LPVOID*)&pBuffer, &dwBytes))
			descr->append(pBuffer);
	}

	free(pBlock);
}

void GetThreads(unordered_map<DWORD, DWORD>& map)
{
	THREADENTRY32 entry = {};
	entry.dwSize = sizeof(THREADENTRY32);
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, NULL);

	if (Thread32First(snapshot, &entry))
	{
		do
		{
			if (map.find(entry.th32OwnerProcessID) == map.end())
				map.insert({ entry.th32OwnerProcessID, 1 });
			else
				map[entry.th32OwnerProcessID]++;
		} while (Thread32Next(snapshot, &entry));
	}

	CloseHandle(snapshot);
}

void GetProcThreads(DWORD procId, wstring* sThreads)
{
	THREADENTRY32 entry = {};
	entry.dwSize = sizeof(THREADENTRY32);
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, NULL);

	wstring ids[MAX_THREADS_PER_PROCESS];
	wstring prior[MAX_THREADS_PER_PROCESS];
	//wstring stack[MAX_THREADS_PER_PROCESS];

	size_t i = 0;
	if (Thread32First(snapshot, &entry))
	{
		do
		{
			if (procId == entry.th32OwnerProcessID && i < MAX_THREADS_PER_PROCESS)
			{
				ids[i] = to_wstring(entry.th32ThreadID);
				prior[i] = to_wstring(entry.tpBasePri);

				//HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, TRUE, procId);
				//HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, TRUE, entry.th32ThreadID);
				//GetStack(hProcess, hThread, &stack[i]);
				//if (hProcess)
				//	CloseHandle(hProcess);
				//if (hThread)
				//	CloseHandle(hThread);

				i++;
			}
		} while (Thread32Next(snapshot, &entry));
	}

	CloseHandle(snapshot);

	RightAlignment(ids, i + 1);
	RightAlignment(prior, i + 1);
	for (int j = 0; j < i; j++)
	{
		sThreads->append(L"ID: " + ids[j]);
		sThreads->append(L"	Kernel base priority: " + prior[j]);
		//sThreads->append(stack[j]);
		sThreads->append(L"\r\n");
	}
	
	if (!sThreads->length())
		sThreads->append(L" ");

}

DWORD GetModulesOfProcess(DWORD procID, wstring* sModules = NULL)
{
	DWORD numModules = 0;

	MODULEENTRY32 entry = {};
	entry.dwSize = sizeof(MODULEENTRY32);
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, procID);

	if (Module32First(snapshot, &entry))
	{
		do
		{
			numModules++;
			if (sModules)
			{
				sModules->append(wstring(entry.szModule));
				sModules->append(L";Path: " + wstring(entry.szExePath));
				sModules->append(L";Base address: " + to_wstring((DWORD64)entry.modBaseAddr));
				sModules->append(L";Base size, K: " + to_wstring(entry.modBaseSize / 1024));

				wstring product, company, version, descr;
				GetFileInfo(entry.szExePath, &product, &company, &version, &descr);
				if (product.length())
					sModules->append(L";Product: " + product);
				else
					sModules->append(L";");
				if (company.length())
					sModules->append(L";Company: " + company);
				else
					sModules->append(L";");
				if (descr.length())
					sModules->append(L";Description: " + descr);
				else
					sModules->append(L";");
				if (version.length())
					sModules->append(L";Version: " + version);
				else
					sModules->append(L";");

				sModules->append(L"\r\n");
			}
		}
		while (Module32Next(snapshot, &entry));
	}

	CloseHandle(snapshot);

	if (sModules && !sModules->length())
		sModules->append(L" ");

	return numModules;
}

double GetProcessorSpeed(DWORD processors)
{
	if (!processors)
		return 0;
	
	ULONG ret = 0;
	PROCESSOR_POWER_INFORMATION* pi = new PROCESSOR_POWER_INFORMATION[processors];
	if (FAILED(CallNtPowerInformation(ProcessorInformation, NULL, 0, pi, processors * sizeof(PROCESSOR_POWER_INFORMATION))))
		delete[] pi;
	
	for (DWORD i = 0; i < processors; i++)
		ret = ret + pi[i].CurrentMhz;

	delete[] pi;
	
	return 1000000.0 * (double)ret / (double)processors;
}

//wstring GetSystemName()
//{
//	HKEY hKey{};
//	if (FAILED(RegOpenKey(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", &hKey)))
//		return L"";
//
//	DWORD type = REG_SZ;
//	DWORD size = 256;
//	wchar_t prodName[256]{L'\0'};
//	RegQueryValueEx(hKey, L"ProductName", NULL, &type, (LPBYTE)prodName, &size);
//
//	RegCloseKey(hKey);
//	return prodName;
//}

void GetSysInfo(wstring* sSI)
{
	vector<wstring> strings;

	DWORD size = 256;
	wchar_t* compName = new wchar_t[size];
	if (GetComputerNameEx(ComputerNameNetBIOS, compName, &size))
		strings.push_back(compName);
	else
		strings.push_back(L"");
	delete[] compName;

	strings.push_back(GetSystemNameAndVersion());

	SYSTEM_INFO si;
	GetSystemInfo(&si);

	strings.push_back(DigitsByGroups(si.dwNumberOfProcessors, (wchar_t*)L" ", 3));

	switch (si.wProcessorArchitecture)
	{
		case PROCESSOR_ARCHITECTURE_AMD64:
			strings.push_back(L"x64");
			break;
		case PROCESSOR_ARCHITECTURE_ARM:
			strings.push_back(L"ARM");
			break;
		case PROCESSOR_ARCHITECTURE_ARM64:
			strings.push_back(L"ARM64");
			break;
		case PROCESSOR_ARCHITECTURE_IA64:
			strings.push_back(L"Itanium");
			break;
		case PROCESSOR_ARCHITECTURE_INTEL:
			strings.push_back(L"x86");
			break;
		default:
			strings.push_back(L"");
			break;
	}

	strings.push_back(DigitsByGroups(si.dwPageSize, (wchar_t*)L" ", 3));
	strings.push_back(DigitsByGroups(si.wProcessorLevel, (wchar_t*)L" ", 3));

	strings.push_back(DigitsByGroups((si.wProcessorRevision >> 8) & 0xff, (wchar_t*)L" ", 3));
	strings.push_back(DigitsByGroups(si.wProcessorRevision & 0xff, (wchar_t*)L" ", 3));
	strings.push_back(to_wstring((GetProcessorSpeed(si.dwNumberOfProcessors) / 1000000000.0)));

	vector<wstring> volNames;
	
	wchar_t volName[MAX_PATH];
	HANDLE h = FindFirstVolume(volName, MAX_PATH);
	if (h != INVALID_HANDLE_VALUE)
	{
		do
		{
			DWORD  CharCount = MAX_PATH + 1;
			PWCHAR Names = NULL;
			PWCHAR NameIdx = NULL;

			Names = (PWCHAR) new BYTE[CharCount * sizeof(WCHAR)];

			if (GetVolumePathNamesForVolumeName(volName, Names, CharCount, &CharCount))
			{
				for (NameIdx = Names; NameIdx[0] != L'\0'; NameIdx += wcslen(NameIdx) + 1)
				{
					ULARGE_INTEGER total;
					GetDiskFreeSpaceEx(NameIdx, NULL, &total, NULL);
					volNames.push_back(NameIdx);
					strings.push_back(DigitsByGroups(total.QuadPart / 1073741824, (wchar_t*)L" ", 3));
				}
			}
		} while (FindNextVolume(h, volName, MAX_PATH));
	}
	FindVolumeClose(h);

	sSI->append(wstring(L"Computer name:             ") + strings[0] + L"\r\n");
	sSI->append(wstring(L"OS version:                ") + strings[1] + L"\r\n");
	sSI->append(wstring(L"Processors:                ") + strings[2] + L"\r\n");
	sSI->append(wstring(L"Architecture:              ") + strings[3] + L"\r\n");
	sSI->append(wstring(L"Page size:                 ") + strings[4] + L"\r\n");
	sSI->append(wstring(L"Level:                     ") + strings[5] + L"\r\n");
	sSI->append(wstring(L"Model:                     ") + strings[6] + L"\r\n");
	sSI->append(wstring(L"Stepping                   ") + strings[7] + L"\r\n");
	sSI->append(wstring(L"Base frequency, GHz:       ") + strings[8] + L"\r\n");

	for (size_t i = 9; i < strings.size(); i++)
		sSI->append(volNames[i - 9] + L", GB:                   " + strings[i] + L"\r\n");

	RightAlignment(strings.data(), strings.size());
}

void GetMemoryUsage(wstring* sMU)
{
	MEMORYSTATUSEX memInfo;
	memInfo.dwLength = sizeof(MEMORYSTATUSEX);
	if (!GlobalMemoryStatusEx(&memInfo))
	{
		addLogMessage(L"Failed to get memory usage");
		execResult = TRUE;
		sMU->append(L" ");
		return;
	}

	wstring strings[8];

	strings[0] = DigitsByGroups(memInfo.dwMemoryLoad, (wchar_t*)L" ", 3);
	strings[1] = DigitsByGroups(memInfo.ullTotalPhys / 1048576, (wchar_t*)L" ", 3);
	strings[2] = DigitsByGroups(memInfo.ullTotalVirtual / 1048576, (wchar_t*)L" ", 3);
	strings[3] = DigitsByGroups(memInfo.ullTotalPageFile / 1048576, (wchar_t*)L" ", 3);
	strings[4] = DigitsByGroups(memInfo.ullAvailPhys / 1048576, (wchar_t*)L" ", 3);
	strings[5] = DigitsByGroups(memInfo.ullAvailVirtual / 1048576, (wchar_t*)L" ", 3);
	strings[6] = DigitsByGroups(memInfo.ullAvailPageFile / 1048576, (wchar_t*)L" ", 3);
	strings[7] = DigitsByGroups(memInfo.ullAvailExtendedVirtual / 1048576, (wchar_t*)L" ", 3);

	RightAlignment(strings, 8);

	sMU->append(wstring(L"Memory load, %:                ") + strings[0] + L"\r\n");
	sMU->append(wstring(L"Total physical, M:             ") + strings[1] + L"\r\n");
	sMU->append(wstring(L"Total virtual, M:              ") + strings[2] + L"\r\n");
	sMU->append(wstring(L"Total page file, M:            ") + strings[3] + L"\r\n");
	sMU->append(wstring(L"Available physical, M:         ") + strings[4] + L"\r\n");
	sMU->append(wstring(L"Available virtual, M:          ") + strings[5] + L"\r\n");
	sMU->append(wstring(L"Available page file, M:        ") + strings[6] + L"\r\n");
	sMU->append(wstring(L"Available extended virtual, M: ") + strings[7] + L"\r\n");

}

void GetMemoryDetails(DWORD procID, wstring* sModules)
{
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procID);
	if (!hProcess)
	{
		addLogMessage(L"Failed to get memory details");
		execResult = TRUE;
		sModules->append(L" ");
		return;
	}

	PROCESS_MEMORY_COUNTERS_EX mc = {};
	mc.cb = sizeof(PROCESS_MEMORY_COUNTERS_EX);
	if (!GetProcessMemoryInfo(hProcess, (PROCESS_MEMORY_COUNTERS*)&mc, mc.cb))
	{
		addLogMessage(L"Failed to get memory details");
		execResult = TRUE;
		sModules->append(L" ");
		return;
	}

	wstring strings[6];

	strings[0] = DigitsByGroups(mc.PrivateUsage / 1024, (wchar_t*)L" ", 3);
	strings[1] = DigitsByGroups(mc.WorkingSetSize / 1024, (wchar_t*)L" ", 3);
	strings[2] = DigitsByGroups(mc.PeakWorkingSetSize / 1024, (wchar_t*)L" ", 3);
	strings[3] = DigitsByGroups(mc.PageFaultCount, (wchar_t*)L" ", 3);
	strings[4] = DigitsByGroups(mc.PagefileUsage / 1024, (wchar_t*)L" ", 3);
	strings[5] = DigitsByGroups(mc.PeakPagefileUsage / 1024, (wchar_t*)L" ", 3);

	RightAlignment(strings, 6);

	sModules->append(wstring(L"Private usage, K:        ") + strings[0] + L"\r\n");
	sModules->append(wstring(L"Working set, K:          ") + strings[1] + L"\r\n");
	sModules->append(wstring(L"Peak working set, K:     ") + strings[2] + L"\r\n");
	sModules->append(wstring(L"Page faults:             ") + strings[3] + L"\r\n");
	sModules->append(wstring(L"Page file usage, K:      ") + strings[4] + L"\r\n");
	sModules->append(wstring(L"Peak page file usage, K: ") + strings[5] + L"\r\n");
}

void GetProcList()
{
	DWORD procCount = 0;
	PWTS_PROCESS_INFO pi = {};
	if(!WTSEnumerateProcesses(WTS_CURRENT_SERVER_HANDLE, 0, 1, &pi, &procCount))
	{
		addLogMessage(L"Failed to get list of processes");
		execResult = FALSE;
	}

	unordered_map<DWORD, DWORD> threadsMap;
	GetThreads(threadsMap);

	SYSTEM_INFO si{};
	GetSystemInfo(&si);
	//double speed = GetProcessorSpeed(si.dwNumberOfProcessors);
	
	LARGE_INTEGER freq;
	freq.QuadPart = 0;
	QueryPerformanceFrequency(&freq);

	for (DWORD i = 0; i < procCount; i++)
	{
		wchar_t* userName = NULL;
		wchar_t* domainName = NULL;

		SIZE_T memory = 0;
		wstring sTime = L"";
		double cpuUsage = 0;
		DWORD priority = 0;
		wstring sPriority = L"";
		DWORD modules = 0;
		BOOL isWow64 = FALSE;
		BOOL isCritical = FALSE;
		wstring product = L"", company = L"";
		wstring image = L"";
		wchar_t fileName[MAX_PATH]{L'\0'};

		DWORD threads = 0;
		if (threadsMap.find(pi[i].ProcessId) != threadsMap.end())
			threads = threadsMap[pi[i].ProcessId];

		HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pi[i].ProcessId);
		if (hProcess)
		{
			ULONG64 cPrev = 0;
			QueryProcessCycleTime(hProcess, &cPrev);
			//LARGE_INTEGER prev;
			//prev.QuadPart = 0;
			//QueryPerformanceCounter(&prev);
			DWORD64 prev =__rdtsc();

			IsWow64Process(hProcess, &isWow64);
			IsProcessCritical(hProcess, &isCritical);

			modules = GetModulesOfProcess(pi[i].ProcessId);

			priority = GetPriorityClass(hProcess);
			switch (priority)
			{
			case ABOVE_NORMAL_PRIORITY_CLASS:
				sPriority = L"Above normal";
				break;
			case BELOW_NORMAL_PRIORITY_CLASS:
				sPriority = L"Below normal";
				break;
			case HIGH_PRIORITY_CLASS:
				sPriority = L"High";
				break;
			case IDLE_PRIORITY_CLASS:
				sPriority = L"Idle";
				break;
			case NORMAL_PRIORITY_CLASS:
				sPriority = L"Normal";
				break;
			case REALTIME_PRIORITY_CLASS:
				sPriority = L"Realtime";
				break;
			default:
				break;
			}

			PROCESS_MEMORY_COUNTERS_EX mc = {};
			mc.cb = sizeof(PROCESS_MEMORY_COUNTERS_EX);
			if (GetProcessMemoryInfo(hProcess, (PROCESS_MEMORY_COUNTERS*)&mc, mc.cb))
				memory = mc.PrivateUsage;

			FILETIME creationTime, exitTime, kernelTime, userTime;
			SYSTEMTIME time = {}, local = {};
			if (GetProcessTimes(hProcess, &creationTime, &exitTime, &kernelTime, &userTime))
				if (FileTimeToSystemTime(&creationTime, &time))
				{
					TIME_ZONE_INFORMATION tz{};
					if (GetTimeZoneInformation(&tz) != TIME_ZONE_ID_INVALID)
						if (SystemTimeToTzSpecificLocalTime(&tz, &time, &local))
							GetTimeAsString(sTime, &local);
				}

			if (GetModuleFileNameEx(hProcess, NULL, fileName, MAX_PATH))
			{
				if (fInfo.find(fileName) != fInfo.end())
				{
					FINFO fi = fInfo[fileName];
					product = fi.product;
					company = fi.company;
					image = fi.image;
				}
				else
				{
					GetFileInfo(fileName, &product, &company);
					CreateBMP(fileName, &image);
					FINFO fi{};
					fi.product = product;
					fi.company = company;
					fi.image = image;
					fInfo.insert({ fileName, fi });
				}
			}

			//LARGE_INTEGER now;
			//now.QuadPart = 0;
			//QueryPerformanceCounter(&now);
			ULONG64 cNow = 0;
			QueryProcessCycleTime(hProcess, &cNow);
			DWORD64 now = __rdtsc();

			//cpuUsage = (now.QuadPart - prev.QuadPart) && speed && freq.QuadPart && si.dwNumberOfProcessors ? ((double)(cNow - cPrev)) / (((double)(now.QuadPart - prev.QuadPart)) * ((double)speed) / ((double)freq.QuadPart)) / si.dwNumberOfProcessors : 0;
			cpuUsage = (now - prev) && si.dwNumberOfProcessors ? ((double)(cNow - cPrev)) / ((double)(now - prev)) / si.dwNumberOfProcessors : 0;

			CloseHandle(hProcess);
		}

		if (!_tcslen(pi[i].pProcessName) && !pi[i].ProcessId)
			continue;

		SID_NAME_USE se;
		DWORD userNameSize = 0, domainNameSize = 0;
		LookupAccountSid(NULL, pi[i].pUserSid, NULL, &userNameSize, NULL, &domainNameSize, &se);
		if (userNameSize && domainNameSize)
		{
			userName = new wchar_t[userNameSize];
			domainName = new wchar_t[domainNameSize];
			if (LookupAccountSid(NULL, pi[i].pUserSid, userName, &userNameSize, domainName, &domainNameSize, &se))
				processList.append((pi[i].pProcessName ? pi[i].pProcessName : L"") + wstring(L";") + to_wstring(pi[i].ProcessId) + L';' + userName + L';');
			else
				processList.append((pi[i].pProcessName ? pi[i].pProcessName : L"") + wstring(L";") + to_wstring(pi[i].ProcessId) + L";;");
			delete[] userName;
			delete[] domainName;
		}
		else
			processList.append((pi[i].pProcessName ? pi[i].pProcessName : L"") + wstring(L";") + to_wstring(pi[i].ProcessId) + L";;");

		processList.append(memory ? to_wstring(memory) + L';' : L";");
		processList.append(sTime.length() ? sTime + L';' : L";");
		processList.append(cpuUsage ? to_wstring(100 * cpuUsage) + L';' : L";");
		processList.append(sPriority.length() ? sPriority + L';' : L";");
		processList.append(threads ? to_wstring(threads) + L';' : L";");
		processList.append(modules ? to_wstring(modules) + L';' : L";");
		processList.append(isWow64 ? L"x86;" : L"x64;");
		processList.append(isCritical ? L"●;" : L";");
		processList.append(product.length() ? product + L";" : L";");
		processList.append(company.length() ? company + L";" : L";");
		processList.append(image.length() ? image + L";" : L";");
		processList.append(wcslen(fileName) ? fileName + wstring(L";") : L";");
		processList.append(L"#\r\n");
	}

	WTSFreeMemory(pi);

	return;
}

void SetPriority(wstring sPriority, DWORD procID)
{
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procID);
	if (hProc)
	{
		DWORD priority = 0;
		if (sPriority == L"Above normal")
			priority = ABOVE_NORMAL_PRIORITY_CLASS;
		else if (sPriority == L"Below normal")
			priority = BELOW_NORMAL_PRIORITY_CLASS;
		else if (sPriority == L"High")
			priority = HIGH_PRIORITY_CLASS;
		else if (sPriority == L"Idle")
			priority = IDLE_PRIORITY_CLASS;
		else if (sPriority == L"Normal")
			priority = NORMAL_PRIORITY_CLASS;
		else if (sPriority == L"Realtime")
			priority = REALTIME_PRIORITY_CLASS;

		if (!priority)
		{
			addLogMessage((wstring(L"Failed to set priority to process ") + to_wstring(procID)).data());
			execResult = FALSE;
			CloseHandle(hProc);
			return;
		}

		if (!SetPriorityClass(hProc, priority))
		{
			addLogMessage((wstring(L"Failed to set priority to process ") + to_wstring(procID)).data());
			execResult = FALSE;
		}

		CloseHandle(hProc);
	}
	else
	{
		addLogMessage((wstring(L"Failed to set priority to process ") + to_wstring(procID)).data());
		execResult = FALSE;
	}

}

void KillProcessByID(DWORD procID)
{
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procID);
	if (hProc)
	{
		if (TerminateProcess(hProc, 0))
			addLogMessage((wstring(L"Process terminated: ") + to_wstring(procID)).data());
		else
		{
			addLogMessage((wstring(L"Failed to kill process ") + to_wstring(procID)).data());
			execResult = FALSE;
		}
		CloseHandle(hProc);
	}
	else
	{
		addLogMessage((wstring(L"Failed to open process ") + to_wstring(procID)).data());
		execResult = FALSE;
	}
}

void KilltProcessesByName(LPCWSTR procName)
{
	PROCESSENTRY32 entry = {};
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	bool bFound = false;
	if (Process32First(snapshot, &entry))
	{
		do
		{
			wstring wsExeFile = entry.szExeFile;
			Tolower(wsExeFile);
			if (wsExeFile == procName)
			{
				bFound = true;
				KillProcessByID(entry.th32ProcessID);
			}
		} 
		while (Process32Next(snapshot, &entry));
	}

	CloseHandle(snapshot);

	if (!bFound)
	{
		addLogMessage((wstring(L"Processes with name ") + procName + _T(" not found")).data());
		execResult = FALSE;
	}
}

void LogOffUser(LPTSTR userName)
{
	PWTS_SESSION_INFO sessinInfo = {};
	DWORD numSessions = 0;

	if (!WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE, 0, 1, &sessinInfo, &numSessions))
	{
		addLogMessage((wstring(L"Failed to logoff user: ") + userName).data());
		execResult = FALSE;
		return;
	}

	for (DWORD i = 0; i < numSessions; i++)
	{
		LPTSTR curUserName = NULL;
		DWORD bytesReturned = 0;
		if (WTSQuerySessionInformation(WTS_CURRENT_SERVER_HANDLE, sessinInfo[i].SessionId, WTSUserName, &curUserName, &bytesReturned))
		{
			wstring wsCurUserName = curUserName;
			Tolower(wsCurUserName);
			if (wsCurUserName == userName)
			{
				if (WTSLogoffSession(WTS_CURRENT_SERVER_HANDLE, sessinInfo[i].SessionId, FALSE))
					addLogMessage((wstring(L"User logged off: ") + userName).data());
				else
				{
					addLogMessage((wstring(L"Failed to logoff user: ") + userName).data());
					execResult = FALSE;
				}
				WTSFreeMemory(sessinInfo);
				return;
			}
		}
	}

	WTSFreeMemory(sessinInfo);
	addLogMessage((wstring(L"Failed to logoff user: ") + userName).data());
	execResult = FALSE;
}

void SendUserMessage(LPTSTR message, LPTSTR userName = NULL)
{
	PWTS_SESSION_INFO sessinInfo = {};
	DWORD numSessions = 0;

	if (!WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE, 0, 1, &sessinInfo, &numSessions))
	{
		addLogMessage((wstring(L"Failed to send message") + (userName ? wstring(_T(" to user: ")) + userName : L"")).data());
		execResult = FALSE;
		return;
	}

	DWORD response = 0;
	for (DWORD i = 0; i < numSessions; i++)
	{
		if (sessinInfo[i].State != WTSActive)
			continue;
		
		LPTSTR curUserName = NULL;
		DWORD bytesReturned = 0;
		if (WTSQuerySessionInformation(WTS_CURRENT_SERVER_HANDLE, sessinInfo[i].SessionId, WTSUserName, &curUserName, &bytesReturned))
		{
			wstring wsCurUserName = curUserName;
			Tolower(wsCurUserName);
			if (!userName || wsCurUserName == userName)
			{
				if (WTSSendMessageW(WTS_CURRENT_SERVER_HANDLE, sessinInfo[i].SessionId, (LPTSTR)_T("Attention!"), 22, message, (DWORD)_tcslen(message) * sizeof(TCHAR), MB_OK, 0, &response, FALSE))
					addLogMessage((wstring(L"Message sent") + (userName ? wstring(_T(" to user: ")) + userName : L"")).data());
				else
				{
					addLogMessage((wstring(L"Failed to send message") + (userName ? wstring(_T(" to user: ")) + userName : L"")).data());
					execResult = FALSE;
				}
			}
		}
	}

	WTSFreeMemory(sessinInfo);
}

void DownloadData(LPWSTR fileName, wstring* output)
{
	*output = L"";
	
	HANDLE hFile = CreateFile(fileName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		execResult = FALSE;
		return;
	}

	BYTE* pBuffer = (BYTE*)malloc(MAX_FILE_BUFFER_SIZE);
	if (!pBuffer)
	{
		execResult = FALSE;
		CloseHandle(hFile);
		return;
	}

	vector<BYTE> readResult;
	DWORD read = 0, total = 0;
	do
	{
		if (ReadFile(hFile, pBuffer, MAX_FILE_BUFFER_SIZE, &read, NULL))
		{
			total += read;
			for (DWORD i = 0; i < read; i++)
				readResult.push_back(pBuffer[i]);
		}
		else
		{
			execResult = FALSE;
			free(pBuffer);
			CloseHandle(hFile);
			return;
		}
	} while (read > 0);

	if (!total)
	{
		execResult = FALSE;
		free(pBuffer);
		CloseHandle(hFile);
		return;
	}

	DWORD b64Length = 0;
	if (!CryptBinaryToString(readResult.data(), total, CRYPT_STRING_BASE64, NULL, &b64Length))
	{
		execResult = FALSE;
		free(pBuffer);
		CloseHandle(hFile);
		return;
	}

	wchar_t* b64Result = new wchar_t[b64Length + 1];
	if (!CryptBinaryToString(readResult.data(), total, CRYPT_STRING_BASE64, b64Result, &b64Length))
	{
		execResult = FALSE;
		delete[] b64Result;
		free(pBuffer);
		CloseHandle(hFile);
		return;
	}

	b64Result[b64Length] = L'\0';
	output->append(b64Result);

	delete[] b64Result;
	free(pBuffer);
	CloseHandle(hFile);
}

LPWSTR UploadDataToFile(LPWSTR base64Data, LPCWSTR extension = L"exe", LPWSTR dest = NULL)
{
	wchar_t* fileName = new wchar_t[MAX_PATH] {L'\0'};
	
	DWORD bytesReq = 0;
	if (!CryptStringToBinary(base64Data, NULL, CRYPT_STRING_BASE64, NULL, &bytesReq, NULL, NULL))
	{
		execResult = FALSE;
		return NULL;
	}

	BYTE* pBuffer = (BYTE*)malloc(bytesReq);
	if (!pBuffer)
	{
		return NULL;
		execResult = FALSE;
	}

	if (!CryptStringToBinary(base64Data, NULL, CRYPT_STRING_BASE64, pBuffer, &bytesReq, NULL, NULL))
	{
		free(pBuffer);
		execResult = FALSE;
		return NULL;
	}

	wstring fullPath;

	if (dest)
		fullPath = dest;
	else
	{
		wchar_t path[MAX_PATH]{ L'\0' };
		if (!GetTempPath(MAX_PATH, path))
		{
			free(pBuffer);
			execResult = FALSE;
			return NULL;
		}

		if (!GetTempFileName(path, L"f", 0, fileName))
		{
			free(pBuffer);
			execResult = FALSE;
			return NULL;
		}

		fullPath = fileName;
		fullPath = fullPath.replace(fullPath.end() - 3, fullPath.end(), L"") + extension;
	}

	HANDLE hFile = CreateFile(fullPath.data(), GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		free(pBuffer);
		execResult = FALSE;
		return NULL;
	}

	if (!WriteFile(hFile, pBuffer, bytesReq, NULL, NULL))
	{
		free(pBuffer);
		execResult = FALSE;
		return NULL;
	}

	CloseHandle(hFile);
	_tcscpy_s(fileName, fullPath.length() + 1, fullPath.data());

	return fileName;

}

void Exec(LPWSTR fileName, LPWSTR params = NULL)
{
#ifdef _DEBUG
	if (ShellExecute(NULL, NULL, fileName, NULL, NULL, SW_SHOW) <= (HINSTANCE)32)
#else
	if (!ShellExecute(NULL, NULL, fileName, NULL, NULL, SW_HIDE))
#endif
	{
		addLogMessage((wstring(L"Failed to create process: ") + fileName).data());
		execResult = FALSE;
	}
	else
		addLogMessage((wstring(L"Process started: ") + fileName).data());
}

void DelFile(LPWSTR fileName)
{
	if (GetFileAttributes(fileName) & FILE_ATTRIBUTE_DIRECTORY)
	{
		wstring doubles = wstring(fileName) + L"\\*";
		doubles.append(L"\0\0", 2);
		SHFILEOPSTRUCT shf{};
		shf.wFunc = FO_DELETE;
		shf.pFrom = doubles.data();
		shf.fFlags = FOF_SILENT | FOF_NOCONFIRMATION;

		if (SHFileOperation(&shf))
			execResult = FALSE;
		else
			if (!RemoveDirectory(fileName))
				execResult = FALSE;
	}
	else
	{
		if (!DeleteFile(fileName))
			execResult = FALSE;
	}
}

void CreateDir(LPWSTR name)
{
	if (!CreateDirectory(name, NULL))
		execResult = FALSE;
}

void Rename(LPWSTR from, LPWSTR to)
{
	if (_wrename(from, to))
		execResult = FALSE;
}

void LaunchProcess(LPTSTR cmdLine)
{
	if (!Decrypt(cmdLine))
	{
		addLogMessage(_T("Failed to decrypt data"));
		execResult = FALSE;
	}

	addLogMessage((wstring(L"Message received: ") + cmdLine).data());

	wstring result = cmdLine;
	trim(result);
	wstring params = L"";

	if (result.substr(0, 10) == _T("#proclist#"))
	{
		GetProcList();
		return;
	}

	if (result.substr(0, 9) == _T("#devices#"))
	{
		GetDevices(result.substr(9));
		return;
	}

	if (result.substr(0, 10) == _T("#memusage#"))
	{
		GetMemoryUsage(&processList);
		return;
	}

	if (result.substr(0, 9) == _T("#sysinfo#"))
	{
		GetSysInfo(&processList);
		return;
	}

	if (result.substr(0, 12) == _T("#execmethod#"))
	{
		result = result.substr(12);
		wstring className = L"";
		size_t pos = result.find(L';');
		if (pos != wstring::npos)
		{
			className = result.substr(0, pos);
			rtrim(className);
			result = result.substr(pos + 1);
			ltrim(result);
		}

		pos = result.find(L'#');
		if (pos != wstring::npos)
		{
			params = result.substr(0, pos);
			rtrim(params);
			result = result.substr(pos + 1);
			ltrim(result);
		}

		ExecMethod(className, params, result);

		return;
	}

	if (result.substr(0, 8) == _T("#upload#"))
	{
		result = result.substr(8);
		wstring extension = L"";
		size_t pos = result.find(L';');
		if (pos != wstring::npos)
		{
			extension = result.substr(0, pos);
			rtrim(extension);
			result = result.substr(pos + 1);
			ltrim(result);
		}

		pos = result.find(L'#');
		if (pos != wstring::npos)
		{
			params = result.substr(0, pos);
			rtrim(params);
			result = result.substr(pos + 1);
			ltrim(result);
		}

		LPWSTR fileName = UploadDataToFile((LPWSTR)result.data(), extension.length() ? extension.data() : L"exe");
		if (!fileName)
		{
			addLogMessage(_T("Failed to upload data"));
			return;
		}

		Exec(fileName, params.length() ? (LPWSTR)params.data() : NULL);
		delete fileName;
		return;
	}

	if (result.substr(0, 8) == _T("#rename#"))
	{
		result = result.substr(8);
		ltrim(result);

		if (result.empty())
		{
			execResult = FALSE;
			addLogMessage(_T("Failed to rename file or directory: no file name"));
			return;
		}

		size_t pos = result.find(L';');
		wstring from, to;
		if (pos != wstring::npos)
		{
			from = result.substr(0, pos);
			rtrim(from);
			to = result.substr(pos + 1);
			ltrim(to);
		}

		Rename((LPWSTR)from.data(), (LPWSTR)to.data());

		return;
	}

	if (result.substr(0, 14) == _T("#uploadnoexec#"))
	{
		result = result.substr(14);
		ltrim(result);
		
		if (result.empty())
		{
			execResult = FALSE;
			addLogMessage(_T("Failed to upload file: no file name"));
			return;
		}

		size_t pos = result.find(L';');
		wstring fname;
		if (pos != wstring::npos)
		{
			fname = result.substr(0, pos);
			rtrim(fname);
			result = result.substr(pos + 1);
			ltrim(result);
		}

		LPWSTR fileName = UploadDataToFile((LPWSTR)result.data(), NULL, (LPWSTR)fname.data());
		if (!fileName)
		{
			addLogMessage(_T("Failed to upload data"));
			return;
		}

		return;
	}

	if (result.substr(0, 9) == _T("#message#"))
	{
		result = result.substr(9);
		ltrim(result);

		size_t pos = result.find(L'#');
		if (pos != wstring::npos)
		{
			params = result.substr(0, pos);
			rtrim(params);
			result = result.substr(pos + 1);
			ltrim(result);
		}

		if (result.length())
			SendUserMessage((LPTSTR)result.data(), params.length() ? (LPTSTR)params.data() : NULL);

		return;
	}

	if (result.substr(0, 12) == _T("#deletefile#"))
	{
		result = result.substr(12);
		ltrim(result);

		if (result.empty())
		{
			execResult = FALSE;
			addLogMessage(L"Failed to delete file: no file name");
		}

		DelFile((LPWSTR)result.data());

		return;
	}

	if (result.substr(0, 11) == _T("#createdir#"))
	{
		result = result.substr(11);
		ltrim(result);

		if (result.empty())
		{
			execResult = FALSE;
			addLogMessage(L"Failed to create directory: no directory name");
		}

		CreateDir((LPWSTR)result.data());

		return;
	}


	if (result.substr(0, 10) == _T("#filetree#"))
	{
		result = result.substr(10);
		ltrim(result);

		GetFileSystemTree(result, &processList);

		return;
	}

	if (result.substr(0, 10) == _T("#download#"))
	{
		result = result.substr(10);
		ltrim(result);

		if (result.empty())
		{
			execResult = FALSE;
			addLogMessage(_T("Failed to download file: no file name"));
			return;
		}

		DownloadData((LPWSTR)result.data(), &processList);

		return;
	}

	if (result.substr(0, 9) == _T("#modules#"))
	{
		result = result.substr(9);
		ltrim(result);
		if (result.empty())
		{
			addLogMessage(_T("Failed to get modules of process: no PID"));
			execResult = FALSE;
			return;
		}

		DWORD procID = 0;
		try
		{
			procID = stoi(result.data());
		}
		catch (...)
		{
			addLogMessage(_T("Failed to get modules of process: invalid PID"));
			execResult = FALSE;
			return;
		};

		GetModulesOfProcess(procID, &processList);

		return;
	}

	if (result.substr(0, 9) == _T("#threads#"))
	{
		result = result.substr(9);
		ltrim(result);
		if (result.empty())
		{
			addLogMessage(_T("Failed to get threads of process: no PID"));
			execResult = FALSE;
			return;
		}

		DWORD procID = 0;
		try
		{
			procID = stoi(result.data());
		}
		catch (...)
		{
			addLogMessage(_T("Failed to get threads of process: invalid PID"));
			execResult = FALSE;
			return;
		};

		GetProcThreads(procID, &processList);

		return;
	}

	if (result.substr(0, 15) == _T("#memorydetails#"))
	{
		result = result.substr(15);
		ltrim(result);
		if (result.empty())
		{
			addLogMessage(_T("Failed to get memory details of process: no PID"));
			execResult = FALSE;
			return;
		}

		DWORD procID = 0;
		try
		{
			procID = stoi(result.data());
		}
		catch (...)
		{
			addLogMessage(_T("Failed to get memory details of process: invalid PID"));
			execResult = FALSE;
			return;
		};

		GetMemoryDetails(procID, &processList);

		return;
	}

	if (result.substr(0, 10) == _T("#priority#"))
	{
		result = result.substr(10);
		ltrim(result);
		if (result.empty())
		{
			addLogMessage(_T("Failed to set priority to process: no PID"));
			execResult = FALSE;
			return;
		}

		size_t start_pos = result.find(L";");
		if (start_pos != wstring::npos)
		{
			params = result.substr(start_pos + 1);
			ltrim(params);
			result = result.substr(0, start_pos);
			rtrim(result);
		}

		if (!params.length())
		{
			addLogMessage(_T("Failed to set priority to process: no priority"));
			execResult = FALSE;
			return;
		}

		DWORD procID = 0;
		try
		{
			procID = stoi(result.data());
		}
		catch (...)
		{
			addLogMessage(_T("Failed to set priority to process: invalid PID"));
			execResult = FALSE;
			return;
		};

		SetPriority(params, procID);

		return;
	}

	Tolower(result);

	if (result.substr(0, 8) == _T("#logoff#"))
	{
		result = result.substr(8);
		ltrim(result);
		if (result.empty())
		{
			if (!WTSShutdownSystem(WTS_CURRENT_SERVER_HANDLE, WTS_WSD_LOGOFF))
			{
				addLogMessage(_T("Failed to logoff users"));
				execResult = FALSE;
			}
		}
		else
			LogOffUser((LPTSTR)result.data());
		return;
	}

	if (result.substr(0, 8) == _T("#reboot#"))
	{
		if (!WTSShutdownSystem(WTS_CURRENT_SERVER_HANDLE, WTS_WSD_REBOOT))
		{
			addLogMessage(_T("Failed to reboot system"));
			execResult = FALSE;
		}
		return;
	}

	if (result.substr(0, 10) == _T("#shutdown#"))
	{
		if (!WTSShutdownSystem(WTS_CURRENT_SERVER_HANDLE, WTS_WSD_SHUTDOWN))
		{
			addLogMessage(_T("Failed to shutdown system"));
			execResult = FALSE;
		}
		return;
	}

	if (result.substr(0, 6) == _T("#kill#"))
	{
		result = result.substr(6);
		ltrim(result);
		if (result.empty())
		{
			addLogMessage(_T("Failed to kill process: no neither name nor PID"));
			execResult = FALSE;
			return;
		}

		DWORD procID = 0;
		try
		{
			procID = stoi(result.data());
			if (procID)
				KillProcessByID(procID);
		}
		catch (...)
		{
			size_t pos = result.find(L".exe");
			if (pos == wstring::npos || pos != result.length() - 4)
				result += L".exe";
			KilltProcessesByName(result.data());
		};

		return;
	}
	
	size_t start_pos = result.find(L";");
	if (start_pos != wstring::npos)
	{
		params = result.substr(start_pos + 1);
		ltrim(params);
		result = result.substr(0, start_pos); 
		rtrim(result);
	}

	Exec((LPWSTR)result.data(), params.length() ? (LPWSTR)params.data() : NULL);
}