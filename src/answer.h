#ifndef ANSWER_H
#define ANSWER_H

#include "main.h"

int status_of(const char *answer, size_t length);
const char *filter(struct client *client);

#endif
