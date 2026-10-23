#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "answer.h"
#include "request.h"

#define MAX_DEPTH 64

static char *skip_space(char *p, char *end) {
	while (p < end && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')) {
		p++;
	}
	return p;
}

static char *skip_string(char *p, char *end) {
	for (p++; p < end; p++) {
		if (*p == '\\') {
			if (++p == end) return NULL;
		} else if (*p == '"') {
			return p + 1;
		}
	}
	return NULL;
}

static char *skip_value(char *p, char *end) {
	char closing[MAX_DEPTH];
	int depth = 0;
	do {
		p = skip_space(p, end);
		if (p == end) return NULL;
		if (*p == '"') {
			p = skip_string(p, end);
			if (!p) return NULL;
		} else if (*p == '{' || *p == '[') {
			if (depth == MAX_DEPTH) return NULL;
			closing[depth++] = *p == '{' ? '}' : ']';
			p++;
		} else if (*p == '}' || *p == ']') {
			if (!depth || closing[--depth] != *p) return NULL;
			p++;
		} else if (depth && (*p == ',' || *p == ':')) {
			p++;
		} else if (is_alnum(*p) || *p == '-' || *p == '+' || *p == '.') {
			while (p < end && (is_alnum(*p) || *p == '-' || *p == '+' || *p == '.')) {
				p++;
			}
		} else {
			return NULL;
		}
	} while (depth);
	return p;
}

static int find_member(char *object, char *end, const char *name, char **comma, char **member, char **value, char **after) {
	size_t length = strlen(name);
	char *p = skip_space(object + 1, end), *key;
	int found;
	*comma = NULL;
	if (p < end && *p == '}') return 0;
	for (;;) {
		if (p == end || *p != '"') return -1;
		key = p;
		p = skip_string(p, end);
		if (!p) return -1;
		found = (size_t)(p - key) == length + 2 && !memcmp(key + 1, name, length);
		p = skip_space(p, end);
		if (p == end || *p != ':') return -1;
		*value = skip_space(p + 1, end);
		p = skip_value(*value, end);
		if (!p) return -1;
		if (found) {
			*member = key;
			*after = p;
			return 1;
		}
		p = skip_space(p, end);
		if (p < end && *p == '}') return 0;
		if (p == end || *p != ',') return -1;
		*comma = p;
		p = skip_space(p + 1, end);
	}
}

static int strip_secrets(char *body, size_t *length) {
	static const char *const secrets[][2] = { { "Config", "Env" }, { "ContainerConfig", "Env" }, { "HostConfig", "LogConfig" }, { NULL, "HttpProxy" }, { NULL, "HttpsProxy" } };
	char *end = body + *length, *top = skip_space(body, end), *comma, *member, *object, *value, *after;
	size_t i;
	int found;
	if (top == end || *top != '{' || !(after = skip_value(top, end)) || skip_space(after, end) != end) return 0;
	for (i = 0; i < sizeof(secrets) / sizeof(secrets[0]); i++) {
		object = top;
		found = secrets[i][0] ? find_member(top, end, secrets[i][0], &comma, &member, &object, &after) : 1;
		if (found < 0) return 0;
		if (!found || *object != '{') continue;
		while ((found = find_member(object, end, secrets[i][1], &comma, &member, &value, &after)) == 1) {
			value = skip_space(after, end);
			if (value < end && *value == ',') {
				after = value + 1;
			} else if (comma) {
				member = comma;
			}
			memmove(member, after, (size_t)(end - after));
			end -= after - member;
		}
		if (found < 0) return 0;
	}
	*length = (size_t)(end - body);
	return 1;
}

static int dechunk(char *data, size_t *length) {
	char *read = data, *write = data, *end = data + *length, *line;
	size_t size;
	for (;;) {
		line = memmem(read, (size_t)(end - read), "\r\n", 2);
		if (!line || line == read) return 0;
		for (size = 0; read < line; read++) {
			if (hex(*read) < 0 || size > MAX_ANSWER) return 0;
			size = size * 16 + (size_t)hex(*read);
		}
		read += 2;
		if (!size) break;
		if ((size_t)(end - read) < size + 2 || memcmp(read + size, "\r\n", 2)) return 0;
		memmove(write, read, size);
		write += size;
		read += size + 2;
	}
	*length = (size_t)(write - data);
	return 1;
}

int status_of(const char *answer, size_t length) {
	int i;
	if (length < 13 || memcmp(answer, "HTTP/1.", 7) || answer[8] != ' ' || answer[12] != ' ') return 0;
	for (i = 9; i < 12; i++) {
		if (answer[i] < '0' || answer[i] > '9') return 0;
	}
	return (answer[9] - '0') * 100 + (answer[10] - '0') * 10 + answer[11] - '0';
}

const char *filter(struct client *client) {
	char head[128], *body = memmem(client->answer, client->used, "\r\n\r\n", 4), *line, *next, *grown;
	size_t length, offset, content = 0;
	int chunked = 0, sized = 0, n;
	if (!body) return "unreadable answer";
	*body = '\0';
	body += 4;
	length = client->used - (size_t)(body - client->answer);
	for (line = cut(client->answer); line; line = next) {
		next = cut(line);
		if (!strncasecmp(line, "Transfer-Encoding:", 18)) {
			chunked = strstr(line + 18, "chunked") != NULL;
		}
		if (!strncasecmp(line, "Content-Length:", 15)) {
			content = strtoul(line + 15, NULL, 10);
			sized = 1;
		}
	}
	if (chunked ? !dechunk(body, &length) : sized && content > length) return "unreadable answer";
	if (!chunked && sized) {
		length = content;
	}
	if (!strip_secrets(body, &length)) return "unreadable answer";
	n = snprintf(head, sizeof(head), "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n", length);
	if (n < 0 || (size_t)n >= sizeof(head)) return "unreadable answer";
	offset = (size_t)(body - client->answer);
	if ((size_t)n + length > client->size) {
		grown = realloc(client->answer, (size_t)n + length);
		if (!grown) return "out of memory";
		client->answer = grown;
		client->size = (size_t)n + length;
	}
	memmove(client->answer + n, client->answer + offset, length);
	memcpy(client->answer, head, (size_t)n);
	client->used = (size_t)n + length;
	return NULL;
}
