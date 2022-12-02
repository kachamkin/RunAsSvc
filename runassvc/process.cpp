#include "header.h"

void performRestart(int how)
{
	addLogMessage(how == RB_AUTOBOOT ? "Reboot" : "Shutdown");

	this_thread::sleep_for(chrono::milliseconds(5));
	reboot(how);
}

inline vector<int64_t> getProcessPidByName(char* name)
{
	vector<int64_t> ret;
	for (auto const& dir_entry : filesystem::directory_iterator("/proc"))
	{
		if (dir_entry.is_directory())
		{
			string sPid = (dir_entry.path().string() + "/comm");
			sPid = sPid.substr(6);
			sPid = sPid.substr(0, sPid.rfind('/'));
			FILE* f = fopen(("/proc/" + sPid +"/comm").data(), "r");
			if (f)
			{
				char procName[256]{ '\0' };
				size_t size = fread(procName, sizeof(char), 256, f);
				if (size && string(procName) == string(name) + "\n")
				{
					try
					{
						ret.push_back(stoi(sPid));
					}
					catch (...)
					{
					}
				}
				fclose(f);
			}
		}
	}
	return ret;
}

string inline getProcList()
{
	string ret = "";

	for (auto const& dir_entry : filesystem::directory_iterator("/proc"))
	{
		if (dir_entry.is_directory())
		{
			string sPid = (dir_entry.path().string() + "/comm");
			sPid = sPid.substr(6);
			sPid = sPid.substr(0, sPid.rfind('/'));

			FILE* f = fopen(("/proc/" + sPid + "/comm").data(), "r");
			if (f)
			{
				char procName[256]{ '\0' };
				size_t size = fread(procName, sizeof(char), 256, f);

				if (size)
				{
					ret += string(procName) + ";" + sPid + ";";
					ret.erase(ret.find("\n"), 1);
				}
				else
					ret = ";;";

				fclose(f);
			}
			else
				ret = ";;";

			f = fopen(("/proc/" + sPid + "/status").data(), "r");
			if (f)
			{
				char userUid[2048]{ '\0' };
				size_t size = fread(userUid, sizeof(char), 2048, f);

				if (size)
				{
					string sUserUid = string(userUid);

					size_t pos = sUserUid.find("Uid:\t");
					if (pos == string::npos)
						ret += ";";
					else
					{
						string uid = sUserUid.substr(pos + 5);
						uid = uid.substr(0, uid.find("\t"));
						try
						{
							passwd* pass = getpwuid(stoi(uid));
							ret += (pass ? pass->pw_name : "") + string(";");
						}
						catch (...)
						{
							ret += ";";
						}
					}

					pos = sUserUid.find("VmRSS:\t");
					if (pos == string::npos)
						ret += ";";
					else
					{
						string uid = sUserUid.substr(pos + 7);
						uid = uid.substr(0, uid.find(" kB\n"));
						ltrim(uid);
						try
						{
							ret += uid + ";";
						}
						catch (...)
						{
							ret += ";";
						}
					}
				}

				fclose(f);
			}
			else
				ret += ";;";
		}
	}

	ret += "#\r\n";

	return ret;
}

bool inline killProcess(int64_t procID)
{
	if (procID)
	{
		if (!kill(procID, SIGKILL))
		{
			addLogMessage((string("Failed to kill process ") + to_string(procID)).data(), __FILE__, __LINE__);
			return true;
		}
		else
			addLogMessage((string("Process killed: ") + to_string(procID)).data(), __FILE__, __LINE__);

		return false;
	}
	return false;
}

bool inline performKill(string action)
{
	action = action.substr(6);
	ltrim(action);
	if (action.empty())
	{
		addLogMessage("Failed to kill process: no process PID", __FILE__, __LINE__);
		return false;
	}

	int64_t procID = 0;
	try
	{
		return killProcess(stoi(action.data()));
	}
	catch (...)
	{
		bool ret = true;
		for (auto const& procID : getProcessPidByName(action.data()))
		{
			if (!killProcess(procID))
				ret = false;
		}
		return ret;
	};

	return true;
}

bool inline performStart(string action)
{
	string params = "";
	size_t start_pos = action.find(";");
	if (start_pos != wstring::npos)
	{
		params = action.substr(start_pos + 1);
		action = action.substr(0, start_pos);
	}

	ltrim(params);
	rtrim(action);

	if ((int64_t)popen((action + " " + params).data(), "w") <= 0)
	{
		addLogMessage((string("Failed to start process ") + action).data(), __FILE__, __LINE__);
		return false;
	}
	else
		addLogMessage((string("Started ") + action).data(), __FILE__, __LINE__);

	return true;
}

vector<string> inline getActiveUsers()
{
	vector<string> ret;	
	setutent();
	utmp* user = getutent();
	while (user)
	{
		if (user->ut_type == USER_PROCESS)
			ret.push_back(user->ut_user);
	}
	return ret;
}

bool inline performLogoff(string action)
{
	action = action.substr(8);
	ltrim(action);
	if (!action.empty())
		return performStart("pkill;-KILL -u" + action);
	else
	{
		bool ret = true;
		for (auto const& u : getActiveUsers())
		{
			if (!performStart("pkill;-KILL -u" + u))
				ret = false;
		}
		return ret;
	}
}

bool inline performMessage(string action)
{
	action = action.substr(9);
	ltrim(action);

	string params = "";
	size_t pos = action.find(L'#');
	if (pos != string::npos)
	{
		params = action.substr(0, pos);
		rtrim(params);
		action = action.substr(pos + 1);
		ltrim(action);
	}

	if (!action.empty())
		return performStart(params.empty() ? "wall;\"" + action + "\"" : "echo;\"" + action + "\" | write " + params);
	else
	{
		addLogMessage("Failed to send message: no text");
		return false;
	}
}

bool perform(string action)
{
	trim(action);

	if (action.substr(0, 8) == "#reboot#")
	{
		thread(performRestart, RB_AUTOBOOT).detach();
		return true;
	}

	if (action.substr(0, 10) == "#shutdown#")
	{
		thread(performRestart, RB_POWER_OFF).detach();
		return true;
	}

	if (action.substr(0, 6) == "#kill#")
		return performKill(action);

	if (action.substr(0, 8) == "#logoff#")
		return performLogoff(action);

	if (action.substr(0, 9) == "#message#")
		return performMessage(action);

	if (action.substr(0, 10) == "#proclist#")
	{
		getProcList();
		return true;
	}


	return performStart(action);
}