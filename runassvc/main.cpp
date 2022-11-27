#include "header.h"

void addLogMessage(const char* message, const char* file, int line)
{
    openlog(SERVICE_NAME, LOG_NDELAY, LOG_DAEMON);
	if (file != NULL)
		syslog(LOG_INFO, (string("File ") + file + ", line " + to_string(line) + " - " + message).data());
	else
		syslog(LOG_INFO, message);
	closelog();
}

int main(int argc, char* argv[])
{
	addLogMessage("Started");

	string workingDir(argv[0]);
	size_t pos = workingDir.rfind('/');
	workingDir = pos == string::npos ? "" : workingDir.substr(0, pos);

	listenForQueries(argc > 1 ? argv[1] : NULL, workingDir);
    return 0;
}