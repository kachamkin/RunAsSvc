#include "header.h"

void restart(int how)
{
	addLogMessage(how == RB_AUTOBOOT ? "Reboot" : "Shutdown");

	this_thread::sleep_for(chrono::milliseconds(5));
	reboot(how);
}

bool perform(string action)
{
	trim(action);
	
	if (action.substr(0, 8) == "#reboot#")
	{
		thread(restart, RB_AUTOBOOT).detach();
		return true;
	}

	if (action.substr(0, 10) == "#shutdown#")
	{
		thread(restart, RB_POWER_OFF).detach();
		return true;
	}

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