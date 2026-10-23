#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "answer.h"
#include "main.h"
#include "request.h"

#define LISTEN_PATH "/run/beszel-docker-gate/docker.sock"
#define DOCKER_PATH "/var/run/docker.sock"
#define MAX_CLIENTS 16
#define REQUEST_TIMEOUT 10
#define CONNECTION_TIMEOUT 60

static volatile sig_atomic_t running = 1;
static sigset_t unblocked;
static const char *listen_path = LISTEN_PATH;
static struct sockaddr_un docker_address = { .sun_family = AF_UNIX };
static char buffers[MAX_CLIENTS][BUFFER_SIZE] __attribute__((aligned(4096)));
static unsigned int active;

static void stop(int sig) {
	(void)sig;
	running = 0;
}

void note(const char *format, ...) {
	char stamp[32] = "", message[384];
	time_t now = time(NULL);
	struct tm *local = localtime(&now);
	va_list args;
	if (local && !getenv("JOURNAL_STREAM")) {
		strftime(stamp, sizeof(stamp), "%Y-%m-%d %H:%M:%S ", local);
	}
	va_start(args, format);
	vsnprintf(message, sizeof(message), format, args);
	va_end(args);
	fprintf(stderr, "%s%s\n", stamp, message);
}

static time_t seconds(void) {
	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);
	return now.tv_sec;
}

static void identify(int fd, char *who, size_t size) {
	struct ucred peer;
	socklen_t length = sizeof(peer);
	char path[32], text[1024];
	ssize_t n = -1;
	int file, i, run = 0;
	if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &peer, &length) < 0) {
		snprintf(who, size, "unknown client");
		return;
	}
	snprintf(who, size, "pid %d", (int)peer.pid);
	snprintf(path, sizeof(path), "/proc/%d/cgroup", (int)peer.pid);
	file = open(path, O_RDONLY | O_CLOEXEC);
	if (file >= 0) {
		n = read(file, text, sizeof(text));
		close(file);
	}
	for (i = 0; i < n; i++) {
		run = hex(text[i]) >= 0 ? run + 1 : 0;
		if (run == 64 && (i + 1 == n || hex(text[i + 1]) < 0)) {
			snprintf(who, size, "container %.12s", text + i - 63);
			return;
		}
	}
}

static void set_group(void) {
	struct stat docker;
	if (stat(docker_address.sun_path, &docker) == 0 && chown(listen_path, (uid_t)-1, docker.st_gid) < 0) {
		note("%s: %s", listen_path, strerror(errno));
	}
}

static int open_docker(void) {
	static int failing = -1;
	int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (fd >= 0 && connect(fd, (struct sockaddr *)&docker_address, sizeof(docker_address)) == 0) {
		if (failing == 1) {
			note("Docker reachable again");
		}
		if (failing) {
			set_group();
		}
		failing = 0;
		return fd;
	}
	if (failing != 1) {
		note("cannot reach Docker at %s: %s", docker_address.sun_path, strerror(errno));
	}
	failing = 1;
	if (fd >= 0) {
		close(fd);
	}
	return -1;
}

static void drop(struct client *client) {
	static long page;
	uintptr_t start, stop;
	if (!page) {
		page = sysconf(_SC_PAGESIZE);
	}
	close(client->fd);
	if (client->docker >= 0) {
		close(client->docker);
	}
	free(client->answer);
	client->fd = -1;
	client->docker = -1;
	client->answer = NULL;
	client->stage = FREE;
	if (--active || page <= 0) return;
	start = ((uintptr_t)buffers + (uintptr_t)page - 1) & ~((uintptr_t)page - 1);
	stop = ((uintptr_t)buffers + sizeof(buffers)) & ~((uintptr_t)page - 1);
	if (start < stop) {
		madvise((void *)start, stop - start, MADV_DONTNEED);
	}
}

static void reply(struct client *client, int code) {
	const char *status = code == 400 ? "400 Bad Request" : code == 403 ? "403 Forbidden" : "502 Bad Gateway";
	const char *message = code == 400 ? "bad request" : code == 403 ? "denied by beszel-docker-gate" : "beszel-docker-gate cannot answer";
	char response[256];
	int length;
	length = snprintf(response, sizeof(response), "HTTP/1.1 %s\r\nContent-Type: application/json\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n{\"message\":\"%s\"}\n", status, strlen(message) + 15, message);
	if (length > 0 && (size_t)length < sizeof(response)) {
		send(client->fd, response, (size_t)length, MSG_NOSIGNAL);
	}
	drop(client);
}

static void refuse(struct client *client, int code, const struct request *request) {
	static char last[320];
	char message[320], who[32];
	size_t length;
	identify(client->fd, who, sizeof(who));
	if (code != 403) {
		snprintf(message, sizeof(message), "denied malformed request from %s", who);
	} else if ((length = strlen(request->target)) <= 256) {
		snprintf(message, sizeof(message), "denied %.15s %s from %s", request->method, request->target, who);
	} else {
		snprintf(message, sizeof(message), "denied %.15s %.120s...%s from %s", request->method, request->target, request->target + length - 120, who);
	}
	if (strcmp(message, last)) {
		note("%s", message);
	}
	strcpy(last, message);
	reply(client, code);
}

static void finish(struct client *client, const char *problem) {
	static int failing;
	int status = status_of(client->answer, client->used);
	close(client->docker);
	client->docker = -1;
	client->stage = FLUSH;
	client->sent = 0;
	if (!problem && status && status != 200) return;
	if (!problem) {
		problem = status ? filter(client) : "unreadable answer";
	}
	if (!problem) {
		if (failing) {
			note("Docker answers filtered again");
		}
		failing = 0;
		return;
	}
	if (!failing) {
		note("cannot filter a Docker answer (%s), sent 502 instead", problem);
	}
	failing = 1;
	reply(client, 502);
}

static void collect(struct client *client) {
	char *grown;
	ssize_t n;
	if (client->used == client->size) {
		grown = client->size < MAX_ANSWER ? realloc(client->answer, client->size * 2) : NULL;
		if (!grown) {
			finish(client, client->size < MAX_ANSWER ? "out of memory" : "answer over 4 MiB");
			return;
		}
		client->answer = grown;
		client->size *= 2;
	}
	n = recv(client->docker, client->answer + client->used, client->size - client->used, 0);
	if (n > 0) {
		client->used += (size_t)n;
	} else if (n == 0) {
		finish(client, NULL);
	} else if (errno != EAGAIN) {
		drop(client);
	}
}

static void start(struct client *client, char *end) {
	static char text[BUFFER_SIZE + 256];
	struct request request;
	int code, length;
	*end = '\0';
	code = parse(client->buffer, &request);
	if (code) {
		refuse(client, code, &request);
		return;
	}
	client->docker = open_docker();
	if (client->docker < 0) {
		reply(client, 502);
		return;
	}
	if (request.strip) {
		client->size = 2 * BUFFER_SIZE;
		client->answer = malloc(client->size);
		if (!client->answer) {
			reply(client, 502);
			return;
		}
	}
	length = snprintf(text, sizeof(text), "%s %s %s\r\nHost: localhost\r\n%s%s%sConnection: close\r\n\r\n", request.method, request.target, request.version, request.agent ? "User-Agent: " : "", request.agent ? request.agent : "", request.agent ? "\r\n" : "");
	if (length < 0 || (size_t)length >= sizeof(text) || send(client->docker, text, (size_t)length, MSG_NOSIGNAL) != length) {
		reply(client, 502);
		return;
	}
	client->stage = request.strip ? COLLECT : RELAY;
	client->used = 0;
	client->sent = 0;
}

static void receive(struct client *client) {
	size_t from = client->used > 3 ? client->used - 3 : 0;
	ssize_t n = recv(client->fd, client->buffer + client->used, BUFFER_SIZE - 1 - client->used, 0);
	char *end;
	if (n <= 0) {
		if (n == 0 || errno != EAGAIN) {
			drop(client);
		}
		return;
	}
	client->used += (size_t)n;
	client->buffer[client->used] = '\0';
	end = memmem(client->buffer + from, client->used - from, "\r\n\r\n", 4);
	if (end) {
		start(client, end);
	} else if (client->used == BUFFER_SIZE - 1) {
		refuse(client, 400, NULL);
	}
}

static void relay(struct client *client, short from_client, short from_docker) {
	char ignored[512], *out;
	ssize_t n;
	if (from_client & (POLLERR | POLLHUP | POLLNVAL)) {
		drop(client);
		return;
	}
	if (from_client & POLLIN) {
		n = recv(client->fd, ignored, sizeof(ignored), 0);
		if (n == 0) {
			client->eof = 1;
		} else if (n < 0 && errno != EAGAIN) {
			drop(client);
			return;
		}
	}
	if (client->stage == COLLECT) {
		if (from_docker) {
			collect(client);
		}
		if (client->stage != FLUSH) return;
	} else if (from_docker) {
		n = recv(client->docker, client->buffer, BUFFER_SIZE, 0);
		if (n == 0 || (n < 0 && errno != EAGAIN)) {
			drop(client);
			return;
		}
		if (n > 0) {
			client->used = (size_t)n;
			client->sent = 0;
		}
	}
	out = client->stage == FLUSH ? client->answer : client->buffer;
	if (client->sent < client->used) {
		n = send(client->fd, out + client->sent, client->used - client->sent, MSG_NOSIGNAL);
		if (n < 0 && errno != EAGAIN) {
			drop(client);
			return;
		}
		if (n > 0) {
			client->sent += (size_t)n;
		}
	}
	if (client->sent == client->used && client->stage == FLUSH) {
		drop(client);
	} else if (client->sent == client->used) {
		client->used = client->sent = 0;
	}
}

static void accept_clients(int listener, struct client *clients) {
	struct client *client;
	int fd, i;
	for (i = 0; i < MAX_CLIENTS; i++) {
		client = &clients[i];
		if (client->stage != FREE) continue;
		fd = accept4(listener, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
		if (fd < 0) return;
		client->stage = REQUEST;
		client->fd = fd;
		client->docker = -1;
		client->buffer = buffers[i];
		active++;
		client->eof = 0;
		client->since = seconds();
		client->used = 0;
		client->sent = 0;
	}
}

static int open_listener(void) {
	struct sockaddr_un address = { .sun_family = AF_UNIX };
	struct stat existing;
	char *slash;
	int fd, error, alive;
	if (strlen(listen_path) >= sizeof(address.sun_path)) {
		errno = ENAMETOOLONG;
		return -1;
	}
	strcpy(address.sun_path, listen_path);
	slash = strrchr(address.sun_path, '/');
	if (slash && slash != address.sun_path) {
		*slash = '\0';
		mkdir(address.sun_path, 0755);
		*slash = '/';
	}
	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (fd < 0) return -1;
	if (lstat(listen_path, &existing) == 0 && S_ISSOCK(existing.st_mode)) {
		alive = connect(fd, (struct sockaddr *)&address, sizeof(address)) == 0 || errno == EAGAIN;
		close(fd);
		if (alive) {
			errno = EADDRINUSE;
			return -1;
		}
		unlink(listen_path);
		fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
		if (fd < 0) return -1;
	}
	if (bind(fd, (struct sockaddr *)&address, sizeof(address)) == 0 && chmod(listen_path, 0660) == 0 && listen(fd, SOMAXCONN) == 0) {
		set_group();
		return fd;
	}
	error = errno;
	close(fd);
	errno = error;
	return -1;
}

int main(int argc, char **argv) {
	static const int signals[] = { SIGHUP, SIGINT, SIGTERM };
	static struct client clients[MAX_CLIENTS];
	static struct pollfd fds[1 + 2 * MAX_CLIENTS];
	struct sigaction action = { .sa_handler = stop }, ignore = { .sa_handler = SIG_IGN };
	const char *docker_path = argc > 2 ? argv[2] : DOCKER_PATH;
	struct timespec second = { .tv_sec = 1 };
	struct client *client;
	int listener, busy, pending;
	unsigned int i;
	sigset_t blocked;
	time_t now;
	if (argc > 1) {
		listen_path = argv[1];
	}
	if (strlen(docker_path) >= sizeof(docker_address.sun_path)) {
		note("%s: %s", docker_path, strerror(ENAMETOOLONG));
		return 1;
	}
	strcpy(docker_address.sun_path, docker_path);
	listener = open_listener();
	if (listener < 0) {
		note("%s: %s", listen_path, strerror(errno));
		return 1;
	}
	sigaction(SIGPIPE, &ignore, NULL);
	sigemptyset(&blocked);
	for (i = 0; i < sizeof(signals) / sizeof(signals[0]); i++) {
		sigaction(signals[i], &action, NULL);
		sigaddset(&blocked, signals[i]);
	}
	sigprocmask(SIG_BLOCK, &blocked, &unblocked);
	for (i = 0; i < MAX_CLIENTS; i++) {
		clients[i].fd = -1;
		clients[i].docker = -1;
	}
	while (running) {
		busy = 0;
		for (i = 0; i < MAX_CLIENTS; i++) {
			client = &clients[i];
			pending = (client->stage == RELAY || client->stage == FLUSH) && client->sent < client->used;
			fds[1 + 2 * i].fd = client->fd;
			fds[1 + 2 * i].events = (short)((client->eof ? 0 : POLLIN) | (pending ? POLLOUT : 0));
			fds[2 + 2 * i].fd = (client->stage == RELAY && !pending) || client->stage == COLLECT ? client->docker : -1;
			fds[2 + 2 * i].events = POLLIN;
			busy += client->stage != FREE;
		}
		fds[0].fd = busy < MAX_CLIENTS ? listener : -1;
		fds[0].events = POLLIN;
		if (ppoll(fds, 1 + 2 * MAX_CLIENTS, busy ? &second : NULL, &unblocked) < 0) continue;
		if (fds[0].revents) {
			accept_clients(listener, clients);
		}
		now = seconds();
		for (i = 0; i < MAX_CLIENTS; i++) {
			client = &clients[i];
			if (client->stage == REQUEST && fds[1 + 2 * i].revents) {
				receive(client);
			} else if (client->stage != FREE && client->stage != REQUEST) {
				relay(client, fds[1 + 2 * i].revents, fds[2 + 2 * i].revents);
			}
			if (client->stage != FREE && now - client->since >= (client->stage == REQUEST ? REQUEST_TIMEOUT : CONNECTION_TIMEOUT)) {
				drop(client);
			}
		}
	}
	for (i = 0; i < MAX_CLIENTS; i++) {
		if (clients[i].stage != FREE) {
			drop(&clients[i]);
		}
	}
	close(listener);
	unlink(listen_path);
	return 0;
}
