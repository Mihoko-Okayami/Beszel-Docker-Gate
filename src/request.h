#ifndef REQUEST_H
#define REQUEST_H

struct request {
	char *method;
	char *target;
	char *version;
	char *agent;
	int strip;
};

int hex(int c);
int is_alnum(int c);
char *cut(char *line);
int parse(char *head, struct request *request);

#endif
