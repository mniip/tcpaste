#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "config.h"

FILE *log_prelude()
{
	FILE *log = fopen(CONFIG_LOG, "a+");
	if(!log)
		abort();
	static char buffer[4096];
	time_t tm = time(NULL);
	strftime(buffer, 4096, "%c", localtime(&tm));
	fprintf(log, "[%s] ", buffer);
	return log;
}

void log_close(FILE *log)
{
	fprintf(log, "\n");
	fclose(log);
}
