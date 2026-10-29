#ifndef MAIN_H
#define MAIN_H

#include <stddef.h>
#include <time.h>

#define BUFFER_SIZE 8192
#define MAX_ANSWER (4 << 20)

enum stage {
	FREE,
	REQUEST,
	RELAY,
	COLLECT,
	FLUSH,
};

struct client {
	enum stage stage;
	int fd;
	int docker;
	time_t since;
	size_t used;
	size_t sent;
	size_t size;
	char *buffer;
	char *answer;
};

__attribute__((format(printf, 1, 2)))
void note(const char *format, ...);

#endif
