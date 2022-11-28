#include "header.h"

void restart(int how)
{
	addLogMessage("Reboot");

	this_thread::sleep_for(chrono::milliseconds(5));
	//reboot(how);
}

bool perform(string action)
{
	if (action.substr(0, 8) == "#reboot#")
		thread(restart, RB_AUTOBOOT).detach();

	return true;
}