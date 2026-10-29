# Beszel-Docker-Gate

Lets the [Beszel](https://github.com/henrygd/beszel) agent monitor Docker containers without giving it control of Docker: the agent gets exactly what Beszel displays and nothing else, even if it is compromised.

Mounting `/var/run/docker.sock` with `:ro` does not do this: the flag protects the socket file, not the API behind it, so the agent can still start a privileged container and take over the host, or read the passwords in the environment of every container.

## Install

Download all files from the latest release. `beszel-docker-gate` runs on any x86_64 Linux. On ARM, such as a Raspberry Pi, use `beszel-docker-gate-aarch64` instead if `getconf LONG_BIT` prints 64, otherwise `beszel-docker-gate-armv7`, or `beszel-docker-gate-armv6` on a Raspberry Pi Zero or 1.

```sh
sha256sum -c SHA256SUMS
install -D -m 755 beszel-docker-gate /usr/local/sbin/beszel-docker-gate
```

Start it with OpenRC (Alpine Linux):

```sh
install -m 755 beszel-docker-gate.initd /etc/init.d/beszel-docker-gate
rc-update add beszel-docker-gate default
rc-service beszel-docker-gate start
```

Or with systemd (Debian, Ubuntu, Fedora, ...):

```sh
install -m 644 beszel-docker-gate.service /etc/systemd/system/beszel-docker-gate.service
systemctl enable --now beszel-docker-gate
```

Give the agent the gate instead of `/var/run/docker.sock`:

```yaml
services:
  beszel-agent:
    volumes:
      - /run/beszel-docker-gate:/run/beszel-docker-gate:ro
    environment:
      DOCKER_HOST: unix:///run/beszel-docker-gate/docker.sock
```

Mount the directory rather than the socket itself, so the agent keeps its access when the service restarts. The socket gets the group of Docker's socket and mode `0660`: the agent image runs as root and uses it as is.

### Podman

With Podman, the gate needs two arguments: its own socket, then Podman's (`/run/podman/podman.sock`, opened by `podman.socket` under systemd or the `podman` service under OpenRC):

- OpenRC: add `command_args="/run/beszel-docker-gate/docker.sock /run/podman/podman.sock"` to `/etc/conf.d/beszel-docker-gate`, then run `rc-service beszel-docker-gate restart`
- systemd: run `systemctl edit beszel-docker-gate` and add the lines below, then run `systemctl restart beszel-docker-gate`

```ini
[Service]
ExecStart=
ExecStart=/usr/local/sbin/beszel-docker-gate /run/beszel-docker-gate/docker.sock /run/podman/podman.sock
```

## What gets through

Only the seven `GET` requests the Beszel agent sends, with exactly the query strings it uses:

| Request | Used by Beszel for |
|---|---|
| `/containers/json` | container list |
| `/containers/{id}/stats?stream=0&one-shot=1` | CPU, memory and network usage |
| `/containers/{id}/json` | container details, Podman health |
| `/containers/{id}/logs?stderr=1&stdout=1&tail={n}&timestamps=1` | log viewer |
| `/images/{name}/json` | image update check |
| `/version` | Docker or Podman detection |
| `/info` | host details |

Settings that often hold passwords are removed before they reach the agent: environment variables (`Config.Env`, which Beszel hides anyway) from the container and image details, the log driver options (`HostConfig.LogConfig`, such as a Loki URL with its key) from the container details, so Beszel's container details no longer show them, and the engine's proxy settings (`HttpProxy`, `HttpsProxy`, which Podman sends unmasked) from `/info`. Logs still go through as containers print them.

Everything else gets `403 Forbidden`, or `400 Bad Request` when the request is malformed, and is logged, including endless streams (`stream=1`, `follow=1`) and costly reads (`size=1`).

## Logs

Only changes are logged: denied requests, with the container that sent them, answers that could not be filtered, and Docker becoming unreachable or reachable again.

```
2026-10-12 14:03:51 denied POST /v1.51/containers/create from container 3f2a1b9c0d4e
```

- OpenRC: `/var/log/beszel-docker-gate.log`
- systemd: `journalctl -u beszel-docker-gate`

## How it works

`beszel-docker-gate` listens on `/run/beszel-docker-gate/docker.sock` and reads one request per connection. When the request is one of the seven above, it connects to the engine's socket (`/var/run/docker.sock` by default), sends a new request made of the method, the path and the `User-Agent` only, with `Connection: close`, and copies Docker's answer back. Nothing else the client sends ever reaches Docker: no other header, no body, no second request.

Paths are read the way Docker reads them, `%2F` included, and must match the table exactly. A path with an empty, `.` or `..` segment, or a character that no Docker name can contain, is denied.

For container and image details and `/info`, it reads Docker's whole answer (up to 4 MiB), removes the settings listed above, and sends the result. If the answer cannot be read as JSON, the agent gets `502 Bad Gateway` and none of the answer.

It is a single process with no threads and an 8 KiB buffer per connection, serves up to 64 connections at a time (Beszel uses a few, or one per running container with Docker 24 and older), gives its memory back once no connection is open, and uses no CPU while idle. A connection that has not sent its request after 10 seconds, or is still open after 60 seconds, is closed. The release binary is a static PIE: no dependency, address randomisation, stack protector, fortified memory copies.

## License

Beszel-Docker-Gate is released under the [MIT license](LICENSE).

## Third-party software

The binaries contain [musl](https://musl.libc.org) (MIT). Its license is in [`licenses/`](licenses), which the source code archive of each release includes.
