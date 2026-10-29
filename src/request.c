#include <string.h>
#include <strings.h>

#include "main.h"
#include "request.h"

#define MAX_SEGMENTS 32

struct rule {
	const char *path;
	const char *query;
	int strip;
};

static const struct rule rules[] = {
	{ "containers/json", "", 0 },
	{ "containers/*/json", "", 1 },
	{ "containers/*/stats", "stream=0&one-shot=1", 0 },
	{ "containers/*/logs", "stderr=1&stdout=1&tail=#&timestamps=1", 0 },
	{ "images/**/json", "", 1 },
	{ "version", "", 0 },
	{ "info", "", 1 },
};

int hex(int c) {
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

int is_alnum(int c) {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
}

static int is_name(int c) {
	return is_alnum(c) || c == '-' || c == '_' || c == '.' || c == ':' || c == '@' || c == '[' || c == ']';
}

static int match(const char *pattern, char *const *segments, int count) {
	size_t length = strcspn(pattern, "/");
	const char *rest = pattern[length] ? pattern + length + 1 : pattern + length;
	if (!*pattern) return !count;
	if (!count) return 0;
	if (length == 2 && !strncmp(pattern, "**", 2)) return match(rest, segments + 1, count - 1) || match(pattern, segments + 1, count - 1);
	if ((length == 1 && *pattern == '*') || (strlen(*segments) == length && !strncmp(*segments, pattern, length))) return match(rest, segments + 1, count - 1);
	return 0;
}

static int is_param(const char *param, size_t length, const char *allowed, size_t size) {
	const char *digits = memchr(allowed, '#', size);
	if (!digits) return length == size && !memcmp(param, allowed, size);
	size = (size_t)(digits - allowed);
	if (length <= size || memcmp(param, allowed, size)) return 0;
	for (param += size, length -= size; length; param++, length--) {
		if (*param < '0' || *param > '9') return 0;
	}
	return 1;
}

static int match_query(const char *query, const char *allowed) {
	unsigned int used = 0, count = 0, k;
	const char *item;
	size_t length, size = 0;
	for (; *query; query += length + (query[length] == '&')) {
		length = strcspn(query, "&");
		for (k = 0, item = allowed; *item; k++, item += size + (item[size] == '&')) {
			size = strcspn(item, "&");
			if (!(used & 1u << k) && is_param(query, length, item, size)) break;
		}
		if (!*item) return 0;
		used |= 1u << k;
		count++;
	}
	for (k = 0, item = allowed; *item; k++, item += size + (item[size] == '&')) {
		size = strcspn(item, "&");
	}
	return count == k;
}

static const struct rule *find_rule(const char *target) {
	static char path[BUFFER_SIZE];
	char *segments[MAX_SEGMENTS], *segment, *slash;
	const char *query;
	int c, high, low, count = 0;
	size_t i, n = 0;
	for (i = 0; target[i] && target[i] != '?'; i++) {
		c = (unsigned char)target[i];
		if (c == '%') {
			high = hex(target[i + 1]);
			low = high < 0 ? -1 : hex(target[i + 2]);
			if (low < 0) return NULL;
			c = high << 4 | low;
			i += 2;
		}
		if (c != '/' && !is_name(c)) return NULL;
		path[n++] = (char)c;
	}
	path[n] = '\0';
	query = target[i] ? target + i + 1 : target + i;
	for (segment = path + 1; segment; segment = slash ? slash + 1 : NULL) {
		slash = strchr(segment, '/');
		if (slash) {
			*slash = '\0';
		}
		if (!*segment || !strcmp(segment, ".") || !strcmp(segment, "..") || count == MAX_SEGMENTS) return NULL;
		segments[count++] = segment;
	}
	for (i = 0; i < sizeof(rules) / sizeof(rules[0]); i++) {
		if (match(rules[i].path, segments, count) && match_query(query, rules[i].query)) return &rules[i];
	}
	return NULL;
}

char *cut(char *line) {
	char *end = strstr(line, "\r\n");
	if (!end) return NULL;
	*end = '\0';
	return end + 2;
}

static int is_printable(const char *text, char lowest) {
	if (!*text) return 0;
	for (; *text; text++) {
		if (*text < lowest || *text > '~') return 0;
	}
	return 1;
}

int parse(char *head, struct request *request) {
	const struct rule *rule;
	char *line, *next = cut(head), *end;
	request->method = head;
	request->target = strchr(head, ' ');
	request->version = request->target ? strchr(request->target + 1, ' ') : NULL;
	request->agent = NULL;
	if (!request->version) return 400;
	*request->target++ = '\0';
	*request->version++ = '\0';
	while ((line = next)) {
		next = cut(line);
		if (!strncasecmp(line, "User-Agent:", 11)) {
			request->agent = line + 11;
		}
	}
	if (request->agent) {
		request->agent += strspn(request->agent, " \t");
		end = request->agent + strlen(request->agent);
		while (end > request->agent && (end[-1] == ' ' || end[-1] == '\t')) {
			end--;
		}
		*end = '\0';
		if (!*request->agent) {
			request->agent = NULL;
		}
	}
	if ((strcmp(request->version, "HTTP/1.1") && strcmp(request->version, "HTTP/1.0")) || !is_printable(request->method, '!') || !is_printable(request->target, '!') || request->target[0] != '/' || (request->agent && !is_printable(request->agent, ' '))) return 400;
	rule = strcmp(request->method, "GET") ? NULL : find_rule(request->target);
	if (!rule) return 403;
	request->strip = rule->strip;
	return 0;
}
