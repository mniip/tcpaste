#ifndef LOGGING_H_
#define LOGGING_H_

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

extern FILE *log_prelude();
extern void log_close(FILE *);

#define log_append(...) \
	do\
	{\
		FILE *log = log_prelude();\
		fprintf(log, __VA_ARGS__);\
		log_close(log);\
	}\
	while (0)

#define panic(...) do { log_append(__VA_ARGS__); exit(EXIT_FAILURE); } while (0)

#define strerrno strerror(errno)

#endif
