#include <string>
#include <vector>
#include <comdef.h>
#include <Wbemidl.h>

using namespace std;

extern BOOL execResult;
extern wstring processList;

void GetTimeAsString(wstring& sTime, SYSTEMTIME* pTime);

wstring GetSystemNameAndVersion()
{
	if (FAILED(CoInitializeEx(0, COINIT_MULTITHREADED)))
		return L"";

	if (FAILED(CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL)))
	{
		CoUninitialize();
		return L"";
	}

	IWbemLocator* pLoc = NULL;
	if (FAILED(CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc)))
	{
		CoUninitialize();
		return L"";
	}

	IWbemServices* pSvc = NULL;
	if (FAILED(pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULL, NULL, 0, NULL, 0, 0, &pSvc)))
	{
		pLoc->Release();
		CoUninitialize();
		return L"";
	}

	if (FAILED(CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE)))
	{
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return L"";
	}

	IEnumWbemClassObject* pEnumerator = NULL;
	if (FAILED(pSvc->ExecQuery(bstr_t("WQL"), bstr_t("SELECT * FROM Win32_OperatingSystem"), WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator)))
	{
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return L"";
	}

	IWbemClassObject* pclsObj = NULL;
	ULONG uReturn = 0;
	wstring ret = L"";

	while (pEnumerator)
	{
		pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
		if (!uReturn)
			break;

		VARIANT vtName, vtVersion;

		VariantInit(&vtName);
		pclsObj->Get(L"Name", 0, &vtName, 0, 0);

		VariantInit(&vtVersion);
		pclsObj->Get(L"Version", 0, &vtVersion, 0, 0);

		ret.append(vtName.bstrVal);
		ret = ret.substr(0, ret.find(L"|"));
		ret.append(L" ");
		ret.append(vtVersion.bstrVal);

		pclsObj->Release();
	}

	pSvc->Release();
	pLoc->Release();
	CoUninitialize();

	return ret;
}

void GetDevices(wstring className)
{
	if (className.empty())
	{
		processList.append(L" ");
		return;
	}

	if (FAILED(CoInitializeEx(0, COINIT_MULTITHREADED)))
	{
		processList.append(L" ");
		return;
	}

	if (FAILED(CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL)))
	{
		CoUninitialize();
		processList.append(L" ");
		return;
	}

	IWbemLocator* pLoc = NULL;
	if (FAILED(CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc)))
	{
		CoUninitialize();
		processList.append(L" ");
		return;
	}

	IWbemServices* pSvc = NULL;
	if (FAILED(pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULL, NULL, 0, NULL, 0, 0, &pSvc)))
	{
		pLoc->Release();
		CoUninitialize();
		processList.append(L" ");
		return;
	}

	if (FAILED(CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE)))
	{
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		processList.append(L" ");
		return;
	}

	IWbemClassObject* pClass = NULL;
	if (SUCCEEDED(pSvc->GetObject(bstr_t(className.data()), 0, NULL, &pClass, NULL)))
	{
		if (SUCCEEDED(pClass->BeginMethodEnumeration(0)))
		{
			IWbemClassObject* inSig = NULL;
			IWbemClassObject* outSig = NULL;
			OLECHAR null = L'\0';
			BSTR name = SysAllocStringLen(&null, 256);
			while (pClass->NextMethod(0, &name, &inSig, &outSig) != WBEM_S_NO_MORE_DATA)
			{
				processList.append(name);
				processList.append(L"#");
				if (inSig)
					inSig->Release();
				if (outSig)
					outSig->Release();
				inSig = NULL;
				outSig = NULL;
			}
			SysFreeString(name);
			pClass->EndMethodEnumeration();
		}
		pClass->Release();
	}
	processList.append(L"\r\n");

	IEnumWbemClassObject* pEnumerator = NULL;
	if (FAILED(pSvc->ExecQuery(
		bstr_t("WQL"),
		bstr_t((wstring(L"SELECT * FROM ") + className).data()),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
		NULL,
		&pEnumerator)))
	{
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		processList.append(L" ");
		return;
	}

	IWbemClassObject* pclsObj = NULL;
	ULONG uReturn = 0;
	BOOL first = TRUE;
	BSTR* arr = NULL;
	LONG count = 0;

	while (pEnumerator)
	{
		pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
		if (!uReturn)
			break;

		if (first)
		{
			SAFEARRAY* names = NULL;
			pclsObj->GetNames(NULL, WBEM_FLAG_NONSYSTEM_ONLY, NULL, &names);

			LONG lb = 0, ub = 0;

			SafeArrayAccessData(names, (void**)&arr);
			SafeArrayGetLBound(names, 1, &lb);
			SafeArrayGetUBound(names, 1, &ub);
			SafeArrayUnaccessData(names);

			count = ub - lb + 1;
			for (LONG i = 0; i < count; i++)
			{
				processList.append(arr[i]);
				processList.append(L"#");
			}
			processList.append(L"\r\n");
			first = FALSE;
		}

		VARIANT vtProp{};

		for (LONG i = 0; i < count; i++)
		{
			CIMTYPE type{};
			VariantInit(&vtProp);
			pclsObj->Get(arr[i], 0, &vtProp, &type, 0);

			if (vtProp.vt == VT_BSTR)
			{
				if (type == CIM_DATETIME)
				{
					ISWbemDateTime* pSWbemDateTime = NULL;
					if (SUCCEEDED(CoCreateInstance(CLSID_SWbemDateTime, NULL, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&pSWbemDateTime))))
					{
						if (SUCCEEDED(pSWbemDateTime->put_Value(vtProp.bstrVal)))
						{
							DATE date{};
							SYSTEMTIME st{};
							wstring sTime;
							if (SUCCEEDED(pSWbemDateTime->GetVarDate(TRUE, &date)))
							{
								if (VariantTimeToSystemTime(date, &st))
								{
									GetTimeAsString(sTime, &st);
									processList.append(sTime);
									processList.append(L"#");
								}
								else
								{
									processList.append(vtProp.bstrVal);
									processList.append(L"#");
								}
							}
							else
							{
								processList.append(vtProp.bstrVal);
								processList.append(L"#");
							}
						}
						else
						{
							processList.append(vtProp.bstrVal);
							processList.append(L"#");
						}
						pSWbemDateTime->Release();
					}
					else
					{
						processList.append(vtProp.bstrVal);
						processList.append(L"#");
					}
				}
				else
				{
					processList.append(vtProp.bstrVal);
					processList.append(L"#");
				}
			}
			else if (vtProp.vt == VT_BOOL)
			{
				processList.append(vtProp.boolVal ? L"Yes" : L"No");
				processList.append(L"#");
			}
			else if (vtProp.vt == VT_DATE)
			{
				SYSTEMTIME st{}, local{};
				wstring sTime;

				if (VariantTimeToSystemTime(vtProp.date, &st))
				{
					TIME_ZONE_INFORMATION tz{};
					if (GetTimeZoneInformation(&tz) != TIME_ZONE_ID_INVALID)
						if (SystemTimeToTzSpecificLocalTime(&tz, &st, &local))
							GetTimeAsString(sTime, &local);

					processList.append(sTime);
				}
				processList.append(L"#");
			}
			else if (SUCCEEDED(VariantChangeType(&vtProp, &vtProp, 0, VT_I8)))
			{
				processList.append(to_wstring(vtProp.llVal));
				processList.append(L"#");
			}
			else
				processList.append(L"#");

			VariantClear(&vtProp);
		}

		processList.append(L"\r\n");
		pclsObj->Release();
	}

	if (pEnumerator)
		pEnumerator->Release();
	pSvc->Release();
	pLoc->Release();
	CoUninitialize();
}

void ExecMethod(wstring className, wstring methodName, wstring& filter)
{
	if (className.empty() || methodName.empty())
	{
		execResult = FALSE;
		return;
	}

	vector<wstring> params;
	size_t pos = filter.find(L';');
	if (pos != wstring::npos)
	{
		wstring args = filter.substr(pos + 1);
		filter = pos ? filter.substr(0, pos) : L"";

		pos = args.find(L';');
		if (pos == wstring::npos)
			params.push_back(args);
		while (pos != wstring::npos)
		{
			wstring s = args.substr(0, pos);
			if (s.size())
				params.push_back(s);
			args = args.substr(pos + 1);
			pos = args.find(L';');
		}
	}

	if (FAILED(CoInitializeEx(0, COINIT_MULTITHREADED)))
	{
		execResult = FALSE;
		return;
	}

	if (FAILED(CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL)))
	{
		CoUninitialize();
		execResult = FALSE;
		return;
	}

	IWbemLocator* pLoc = NULL;
	if (FAILED(CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc)))
	{
		CoUninitialize();
		execResult = FALSE;
		return;
	}

	IWbemServices* pSvc = NULL;
	if (FAILED(pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULL, NULL, 0, NULL, 0, 0, &pSvc)))
	{
		pLoc->Release();
		CoUninitialize();
		execResult = FALSE;
		return;
	}

	if (FAILED(CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE)))
	{
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		execResult = FALSE;
		return;
	}

	IWbemClassObject* pClass = NULL;
	if (FAILED(pSvc->GetObject(bstr_t(className.data()), 0, NULL, &pClass, NULL)))
	{
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		execResult = FALSE;
		return;
	}

	IWbemClassObject* inSig = NULL;
	if (FAILED(pClass->GetMethod(methodName.data(), 0, &inSig, NULL)))
	{
		pClass->Release();
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		execResult = FALSE;
		return;
	}

	IWbemClassObject* pInParams = NULL;
	if (inSig)
	{
		if (FAILED(inSig->SpawnInstance(0, &pInParams)))
		{
			inSig->Release();
			pClass->Release();
			pSvc->Release();
			pLoc->Release();
			CoUninitialize();
			execResult = FALSE;
			return;
		}
	}

	if (pInParams && params.size())
	{
		for (size_t i = 0; i < params.size(); i++)
		{
			size_t pos = params[i].find(L'=');
			VARIANT vtVal{};
			vtVal.vt = VT_BSTR;
			vtVal.bstrVal = bstr_t(params[i].substr(pos + 1).data());

			if (FAILED(pInParams->Put(params[i].substr(0, pos).data(), 0, &vtVal, 0)))
			{
				pInParams->Release();
				inSig->Release();
				pClass->Release();
				pSvc->Release();
				pLoc->Release();
				CoUninitialize();
				execResult = FALSE;
				return;
			}
		}
	}

	IWbemClassObject* pOutParams = NULL;
	if (FAILED(pSvc->ExecMethod(bstr_t((className + filter).data()), bstr_t(methodName.data()), 0, NULL, pInParams, &pOutParams, NULL)))
		execResult = FALSE;

	if (pOutParams)
		pOutParams->Release();
	if (pInParams)
		pInParams->Release();
	if (inSig)
		inSig->Release();
	pClass->Release();
	pSvc->Release();
	pLoc->Release();
	CoUninitialize();
}
