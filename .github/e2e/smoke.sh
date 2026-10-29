#!/usr/bin/env bash
set -uo pipefail

BIN=$1
WORK=$(mktemp -d /tmp/beszel-docker-gate.XXXXXX)
LOG=$WORK/gate.log
SOCK=$WORK/run/docker.sock
FAILED=0
PID=
LOST=

ok() { echo "ok   $1"; }
bad() { echo "FAIL $1"; FAILED=$((FAILED + 1)); }
expect() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }
wait_for() { for _ in $(seq 100); do eval "$1" && return 0; sleep 0.1; done; return 1; }
code() { curl -s --path-as-is -o "$WORK/body" -w '%{http_code}' --unix-socket "${3:-$SOCK}" -X "${2:-GET}" "http://localhost$1"; }
trap '[ -z "$PID" ] || kill -KILL "$PID" 2>/dev/null; [ -z "$LOST" ] || kill -KILL "$LOST" 2>/dev/null; docker rm -f gate-smoke >/dev/null 2>&1' EXIT

docker run -d --name gate-smoke -e SMOKE_SECRET=hunter2 -l smoke.pad="$(printf '%070000d' 0)" -l smoke.pad2="$(printf '%070000d' 0)" alpine:latest sleep 120 >/dev/null
"$BIN" "$SOCK" /var/run/docker.sock 2>"$LOG" &
PID=$!
expect "listens on the given socket with mode 0660" 'wait_for "[ -S \"$SOCK\" ]" && [ "$(stat -c %a "$SOCK")" = 660 ]'
expect "passes /version through" '[ "$(code /version)" = 200 ] && grep -q ApiVersion "$WORK/body"'
expect "passes the container list through" '[ "$(code /containers/json)" = 200 ] && jq -e "any(.[]; .Labels[\"smoke.pad\"] + .Labels[\"smoke.pad2\"] | length == 140000)" "$WORK/body" >/dev/null'
expect "passes one-shot stats through" '[ "$(code "/containers/gate-smoke/stats?stream=0&one-shot=1")" = 200 ]'
expect "passes the log tail through" '[ "$(code "/containers/gate-smoke/logs?stderr=1&stdout=1&tail=10&timestamps=1")" = 200 ]'
expect "removes Env and LogConfig from container details" '[ "$(code /containers/gate-smoke/json)" = 200 ] && jq -e ".State and (.Config.Labels[\"smoke.pad\"] + .Config.Labels[\"smoke.pad2\"] | length == 140000) and (.HostConfig | has(\"LogConfig\") | not) and (.Config | has(\"Env\") | not)" "$WORK/body" >/dev/null && ! grep -q hunter2 "$WORK/body"'
expect "removes the proxy settings from /info" '[ "$(code /info)" = 200 ] && jq -e ".OperatingSystem and .NCPU and (has(\"HttpProxy\") or has(\"HttpsProxy\") | not)" "$WORK/body" >/dev/null'
expect "removes Env from image details" '[ "$(code /images/docker.io%2Flibrary%2Falpine:latest/json)" = 200 ] && jq -e "(.RepoDigests | length > 0) and (.Config | has(\"Env\") | not)" "$WORK/body" >/dev/null'
expect "passes a Docker error through unfiltered" '[ "$(code /containers/gate-smoke-missing/json)" = 404 ] && grep -q "No such container" "$WORK/body"'
expect "denies a method other than GET" '[ "$(code /info POST)" = 403 ]'
expect "logs the denied request" 'grep -q "denied POST /info from " "$LOG"'
expect "denies a query string it does not know" '[ "$(code "/containers/json?all=1")" = 403 ]'
expect "denies a streaming stats request" '[ "$(code "/containers/gate-smoke/stats?stream=1&one-shot=1")" = 403 ]'
expect "denies an encoded dot-dot segment" '[ "$(code /images/%2e%2e/json)" = 403 ]'
"$BIN" "$WORK/run/lost.sock" "$WORK/none.sock" 2>"$WORK/lost.log" &
LOST=$!
expect "answers 502 when Docker cannot be reached" 'wait_for "[ -S \"$WORK/run/lost.sock\" ]" && [ "$(code /version GET "$WORK/run/lost.sock")" = 502 ]'
expect "logs that Docker cannot be reached" 'grep -q "cannot reach Docker at " "$WORK/lost.log"'
for pid in "$PID" "$LOST"; do kill -TERM "$pid"; done
timeout 15 tail --pid="$PID" -f /dev/null && wait "$PID"
STATUS=$?
kill -0 "$PID" 2>/dev/null || PID=
wait "$LOST"
kill -0 "$LOST" 2>/dev/null || LOST=
expect "stops on SIGTERM with status 0" '[ "$STATUS" = 0 ]'
expect "removes its socket when it stops" '[ ! -e "$SOCK" ]'
expect "no sanitizer report" '! grep -q "Sanitizer\|runtime error" "$WORK"/*.log'
[ "$FAILED" = 0 ] || { tail -n +1 "$WORK"/*.log; exit 1; }
