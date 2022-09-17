#include <string>
#include <Windows.h>
#include <lmaccess.h>
#include <lmapibuf.h>
#include <sddl.h>

using namespace std;

extern BOOL execResult;

void DeleteUserFromLocalGroup(LPWSTR user, LPWSTR group)
{
	DWORD size = 0, domSize = 0;
	SID_NAME_USE sid_name_use;
	LookupAccountName(NULL, user, NULL, &size, NULL, &domSize, &sid_name_use);
	if (size)
	{
		PSID psid = (PSID)malloc(size);
		if (!psid)
		{
			execResult = FALSE;
			return;
		}
		wchar_t* domName = new wchar_t[domSize];
		if (!LookupAccountName(NULL, user, psid, &size, domName, &domSize, &sid_name_use))
		{
			free(psid);
			delete[] domName;
			execResult = FALSE;
			return;
		}

		LOCALGROUP_MEMBERS_INFO_0 gi{};
		gi.lgrmi0_sid = psid;

		if (ERROR_SUCCESS != NetLocalGroupDelMembers(NULL, group, 0, (LPBYTE)&gi, 1))
			execResult = FALSE;

		free(psid);
		delete[] domName;
	}
}

void DeleteUserFromGroup(LPWSTR user, LPWSTR group)
{
	if (ERROR_SUCCESS != NetGroupDelUser(NULL, group, user))
		execResult = FALSE;
}

void AddUserToLocalGroup(LPWSTR user, LPWSTR group)
{
	DWORD size = 0, domSize = 0;
	SID_NAME_USE sid_name_use;
	LookupAccountName(NULL, user, NULL, &size, NULL, &domSize, &sid_name_use);
	if (size)
	{
		PSID psid = (PSID)malloc(size);
		if (!psid)
		{
			execResult = FALSE;
			return;
		}
		wchar_t* domName = new wchar_t[domSize];
		if (!LookupAccountName(NULL, user, psid, &size, domName, &domSize, &sid_name_use))
		{
			free(psid);
			delete[] domName;
			execResult = FALSE;
			return;
		}

		LOCALGROUP_MEMBERS_INFO_0 gi{};
		gi.lgrmi0_sid = psid;

		if (ERROR_SUCCESS != NetLocalGroupAddMembers(NULL, group, 0, (LPBYTE)&gi, 1))
			execResult = FALSE;

		free(psid);
		delete[] domName;
	}
}

void AddUserToGroup(LPWSTR user, LPWSTR group)
{
	if (ERROR_SUCCESS != NetGroupAddUser(NULL, group, user))
		execResult = FALSE;
}

void AddGroup(LPWSTR name)
{
	GROUP_INFO_0 gi{};
	gi.grpi0_name = name;

	if (ERROR_SUCCESS != NetGroupAdd(NULL, 0, (LPBYTE)&gi, NULL))
		execResult = FALSE;
}

void AddLocalGroup(LPWSTR name)
{
	LOCALGROUP_INFO_0 gi{};
	gi.lgrpi0_name = name;

	if (ERROR_SUCCESS != NetLocalGroupAdd(NULL, 0, (LPBYTE)&gi, NULL))
		execResult = FALSE;
}

void AddUser(LPWSTR name, LPWSTR pass, LPWSTR comment = NULL)
{
	USER_INFO_1 ui{};

	ui.usri1_comment = comment;
	ui.usri1_flags = UF_NORMAL_ACCOUNT;
	ui.usri1_home_dir = NULL;
	ui.usri1_name = name;
	ui.usri1_password = pass;
	ui.usri1_priv = USER_PRIV_USER;
	ui.usri1_script_path = NULL;

	if (ERROR_SUCCESS != NetUserAdd(NULL, 1, (LPBYTE)&ui, NULL))
		execResult = FALSE;
}

void DelGroup(LPWSTR group)
{
	if (ERROR_SUCCESS != NetGroupDel(NULL, group))
		execResult = FALSE;
}

void DelLocalGroup(LPWSTR group)
{
	if (ERROR_SUCCESS != NetLocalGroupDel(NULL, group))
		execResult = FALSE;
}

void DelUser(LPWSTR user)
{
	if (ERROR_SUCCESS != NetUserDel(NULL, user))
		execResult = FALSE;
}

void ChangeUserPassword(LPWSTR user, LPWSTR oldPass, LPWSTR newPass)
{
	if (ERROR_SUCCESS != NetUserChangePassword(NULL, user, oldPass, newPass))
		execResult = FALSE;
}

void GetLocalGroupUsers(LPWSTR group, wstring* output)
{
	LPLOCALGROUP_MEMBERS_INFO_3 pBuf = NULL;
	DWORD dwEntriesRead = 0;
	DWORD dwTotalEntries = 0;

	if (ERROR_SUCCESS == NetLocalGroupGetMembers(NULL, group, 3, (LPBYTE*)&pBuf, MAX_PREFERRED_LENGTH, &dwEntriesRead, &dwTotalEntries, NULL))
	{
		LPLOCALGROUP_MEMBERS_INFO_3 pTmpBuf = pBuf;
		for (DWORD i = 0; i < dwEntriesRead; i++)
		{
			output->append(pTmpBuf->lgrmi3_domainandname);
			if (i != dwEntriesRead - 1)
				output->append(L",");

			pTmpBuf++;
		}
	}

	output->append(L";");

	if (pBuf != NULL)
		NetApiBufferFree(pBuf);
}

void GetGroupUsers(LPWSTR group, wstring* output)
{
	LPGROUP_USERS_INFO_0 pBuf = NULL;
	DWORD dwEntriesRead = 0;
	DWORD dwTotalEntries = 0;

	if (ERROR_SUCCESS == NetGroupGetUsers(NULL, group, 0, (LPBYTE*)&pBuf, MAX_PREFERRED_LENGTH, &dwEntriesRead, &dwTotalEntries, NULL))
	{
		LPGROUP_USERS_INFO_0 pTmpBuf = pBuf;
		for (DWORD i = 0; i < dwEntriesRead; i++)
		{
			output->append(pTmpBuf->grui0_name);
			if (i != dwEntriesRead - 1)
				output->append(L",");

			pTmpBuf++;
		}
	}

	output->append(L";");

	if (pBuf != NULL)
		NetApiBufferFree(pBuf);
}

void GetUserLocalGroups(LPWSTR user, wstring* output)
{
	LPLOCALGROUP_USERS_INFO_0 pBuf = NULL;
	DWORD dwEntriesRead = 0;
	DWORD dwTotalEntries = 0;

	if (ERROR_SUCCESS == NetUserGetLocalGroups(NULL, user, 0, 0, (LPBYTE*)&pBuf, MAX_PREFERRED_LENGTH, &dwEntriesRead, &dwTotalEntries))
	{
		LPLOCALGROUP_USERS_INFO_0 pTmpBuf = pBuf;
		for (DWORD i = 0; i < dwEntriesRead; i++)
		{
			output->append(pTmpBuf->lgrui0_name);
			if (i != dwEntriesRead - 1)
				output->append(L",");

			pTmpBuf++;
		}
	}

	output->append(L";");

	if (pBuf != NULL)
		NetApiBufferFree(pBuf);
}

void GetUserGroups(LPWSTR user, wstring* output)
{
	LPGROUP_USERS_INFO_0 pBuf = NULL;
	DWORD dwEntriesRead = 0;
	DWORD dwTotalEntries = 0;

	if (ERROR_SUCCESS == NetUserGetGroups(NULL, user, 0, (LPBYTE*)&pBuf, MAX_PREFERRED_LENGTH, &dwEntriesRead, &dwTotalEntries))
	{
		LPGROUP_USERS_INFO_0 pTmpBuf = pBuf;
		for (DWORD i = 0; i < dwEntriesRead; i++)
		{
			output->append(pTmpBuf->grui0_name);
			if (i != dwEntriesRead - 1)
				output->append(L",");

			pTmpBuf++;
		}
	}

	output->append(L";");

	if (pBuf != NULL)
		NetApiBufferFree(pBuf);
}

void GetUsers(wstring* output)
{
	PNET_DISPLAY_USER pUser = NULL, p = NULL;
	DWORD res = 0, i = 0, dwRec = 0;

	do
	{
		res = NetQueryDisplayInformation(NULL, 1, i, 100, MAX_PREFERRED_LENGTH, &dwRec, (LPVOID*)&pUser);
		if ((res == ERROR_SUCCESS) || (res == ERROR_MORE_DATA))
		{
			p = pUser;
			for (; dwRec > 0; dwRec--)
			{
				output->append(p->usri1_name);
				output->append(L";");
				output->append(p->usri1_full_name);
				output->append(L";");
				output->append(p->usri1_comment);
				output->append(L";");
				output->append(p->usri1_flags & UF_ACCOUNTDISABLE ? L"Yes" : L"No");
				output->append(L";");
				output->append(p->usri1_flags & UF_LOCKOUT ? L"Yes" : L"No");
				output->append(L";");
				output->append(p->usri1_flags & UF_PASSWORD_EXPIRED ? L"Yes" : L"No");
				output->append(L";");
				output->append(p->usri1_flags & UF_DONT_EXPIRE_PASSWD ? L"Yes" : L"No");
				output->append(L";");

				DWORD size = 0, domSize = 0;
				SID_NAME_USE sid_name_use;
				LookupAccountName(NULL, p->usri1_name, NULL, &size, NULL, &domSize, &sid_name_use);
				if (size)
				{

					PSID psid = (PSID)malloc(size);
					if (!psid)
					{
						output->append(L";");
						output->append(L"\r\n");
						continue;
					}
					wchar_t* domName = new wchar_t[domSize];
					if (!LookupAccountName(NULL, p->usri1_name, psid, &size, domName, &domSize, &sid_name_use))
					{
						free(psid);
						delete[] domName;
						output->append(L";");
						output->append(L"\r\n");
						continue;
					}

					LPWSTR strSid = (LPWSTR)L"";
					ConvertSidToStringSid(psid, &strSid);
					if (wcslen(strSid))
					{
						output->append(strSid);
						output->append(L";");
					}
					else
						output->append(L";");

					GetUserGroups(p->usri1_name, output);
					GetUserLocalGroups(p->usri1_name, output);

					output->append(L"\r\n");

					free(psid);
					delete[] domName;

				}

				i = p->usri1_next_index;
				p++;
			}
		}
		else
			*output = L" ";
		if (pUser)
			NetApiBufferFree(pUser);
	} while (res == ERROR_MORE_DATA);
}

void GetGroups(wstring* output)
{
	PNET_DISPLAY_GROUP pGroup = NULL, p = NULL;
	DWORD res = 0, i = 0, dwRec = 0;

	do
	{
		res = NetQueryDisplayInformation(NULL, 3, i, 100, MAX_PREFERRED_LENGTH, &dwRec, (LPVOID*)&pGroup);
		if ((res == ERROR_SUCCESS) || (res == ERROR_MORE_DATA))
		{
			p = pGroup;
			for (; dwRec > 0; dwRec--)
			{
				output->append(p->grpi3_name);
				output->append(L";");
				output->append(p->grpi3_comment);
				output->append(L";");

				DWORD size = 0, domSize = 0;
				SID_NAME_USE sid_name_use;
				LookupAccountName(NULL, p->grpi3_name, NULL, &size, NULL, &domSize, &sid_name_use);
				if (size)
				{

					PSID psid = (PSID)malloc(size);
					if (!psid)
					{
						output->append(L";");
						output->append(L"\r\n");
						continue;
					}
					wchar_t* domName = new wchar_t[domSize];
					if (!LookupAccountName(NULL, p->grpi3_name, psid, &size, domName, &domSize, &sid_name_use))
					{
						free(psid);
						delete[] domName;
						output->append(L";");
						output->append(L"\r\n");
						continue;
					}

					LPWSTR strSid = (LPWSTR)L"";
					ConvertSidToStringSid(psid, &strSid);
					if (wcslen(strSid))
					{
						output->append(strSid);
						output->append(L";");
					}
					else
						output->append(L";");

					free(psid);
					delete[] domName;

				}

				GetGroupUsers(p->grpi3_name, output);
				output->append(L"\r\n");

				i = p->grpi3_next_index;
				p++;
			}
		}
		else
			*output = L" ";
		if (pGroup)
			NetApiBufferFree(pGroup);
	} while (res == ERROR_MORE_DATA);
}

void GetLocalGroups(wstring* output)
{
	LPLOCALGROUP_INFO_0 pGroup = NULL, p = NULL;
	DWORD res = 0, dwTotal = 0, dwRec = 0;

	do
	{
		res = NetLocalGroupEnum(NULL, 0, (LPBYTE*)&pGroup, MAX_PREFERRED_LENGTH, &dwRec, &dwTotal, NULL);
		if ((res == ERROR_SUCCESS) || (res == ERROR_MORE_DATA))
		{
			p = pGroup;
			for (; dwRec > 0; dwRec--)
			{
				output->append(p->lgrpi0_name);
				output->append(L";");

				DWORD size = 0, domSize = 0;
				SID_NAME_USE sid_name_use;
				LookupAccountName(NULL, p->lgrpi0_name, NULL, &size, NULL, &domSize, &sid_name_use);
				if (size)
				{

					PSID psid = (PSID)malloc(size);
					if (!psid)
					{
						output->append(L";");
						output->append(L"\r\n");
						continue;
					}
					wchar_t* domName = new wchar_t[domSize];
					if (!LookupAccountName(NULL, p->lgrpi0_name, psid, &size, domName, &domSize, &sid_name_use))
					{
						free(psid);
						delete[] domName;
						output->append(L";");
						output->append(L"\r\n");
						continue;
					}

					LPWSTR strSid = (LPWSTR)L"";
					ConvertSidToStringSid(psid, &strSid);
					if (wcslen(strSid))
					{
						output->append(strSid);
						output->append(L";");
					}
					else
						output->append(L";");

					free(psid);
					delete[] domName;

				}
				
				GetLocalGroupUsers(p->lgrpi0_name, output);
				output->append(L"\r\n");

				p++;
			}
		}
		else
			*output = L" ";
		if (pGroup)
			NetApiBufferFree(pGroup);
	} while (res == ERROR_MORE_DATA);
}