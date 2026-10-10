# Sourced by the opencode test scripts. opencode 2.x runs `run` through a managed service ('serve --service',
# 127.0.0.1:49374) that outlives the run; a later run with other XDG dirs then hangs on the busy port (10-08).
# v2_port_pids: PIDs listening on the service port. v2_foreign: is it held by a service that is NOT ours ($1 = our
# XDG_DATA_HOME)? v2_stop_ours: stop only the service whose environment points at our data dir, by PID.
# Linux uses ss + /proc; macOS (no ss, no /proc) uses lsof + `ps eww` (a process's environment, readable for our own
# processes). V2SVC_PORTABLE=1 forces the macOS path (to test it on Linux).
V2_PORT=${V2SVC_PORT:-49374}  # override only to simulate a helper that cannot see the service (tests)
v2_port_pids() {
  if [ -z "${V2SVC_PORTABLE:-}" ] && command -v ss >/dev/null; then ss -ltnpH "sport = :$V2_PORT" 2>/dev/null | grep -o 'pid=[0-9]*' | cut -d= -f2 | sort -u
  else lsof -nP -iTCP:"$V2_PORT" -sTCP:LISTEN -t 2>/dev/null | sort -u; fi
}
v2_is_ours() {
  if [ -z "${V2SVC_PORTABLE:-}" ] && [ -r "/proc/$1/environ" ]; then tr '\0' '\n' < "/proc/$1/environ" | grep -qx "XDG_DATA_HOME=$2"
  else ps eww -o command= -p "$1" 2>/dev/null | tr ' ' '\n' | grep -qx "XDG_DATA_HOME=$2"; fi
}
v2_foreign() { for p in $(v2_port_pids); do v2_is_ours "$p" "$1" || return 0; done; return 1; }
v2_stop_ours() {
  for p in $(v2_port_pids); do v2_is_ours "$p" "$1" && kill "$p" 2>/dev/null; done
  for _ in 1 2 3 4 5 6 7 8 9 10; do v2_port_pids | while read -r p; do v2_is_ours "$p" "$1" && exit 1; done && return 0; sleep 0.5; done
  return 1
}

# Better than sharing the fixed port: give a throwaway home its OWN service port (2.x keeps it in
# <XDG_CONFIG_HOME>/opencode/service.json), so a test never meets the person's own running opencode service (on a Mac
# that uses opencode 2.x daily it is always up). $1 = opencode binary, $2 = root holding cfg/ data/ state/ cache/.
v2_env() { /usr/bin/env XDG_CONFIG_HOME="$2/cfg" XDG_DATA_HOME="$2/data" XDG_STATE_HOME="$2/state" XDG_CACHE_HOME="$2/cache" "$1" "${@:3}"; }
# The port is one the OS reports free (bind to port 0, read it back, release it); a random one if node cannot.
v2_free_port() { node -e "const s=require('net').createServer();s.listen(0,'127.0.0.1',()=>{console.log(s.address().port);s.close()})" 2>/dev/null; }
v2_own_port() {
  V2_PORT=$(v2_free_port); [ -n "$V2_PORT" ] || V2_PORT=$((41000 + RANDOM % 8000))
  v2_env "$1" "$2" service set port "$V2_PORT" >/dev/null 2>&1
}
# Stop that service: opencode's own `service stop` first, then by PID (only ours) if it is still listening.
v2_service_stop() {
  v2_env "$1" "$2" service stop >/dev/null 2>&1
  v2_stop_ours "$2/data"
}
