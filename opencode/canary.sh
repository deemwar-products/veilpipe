#!/usr/bin/env bash
# Canary for Veilpipe in opencode: a real `opencode run` in a throwaway home (XDG dirs), against a local mock model
# (opencode/mock-llm.mjs) that records every request, so it costs nothing and proves what a model would receive.
# The prompt holds a FAKE Stripe key; the model asks for `cat secret.env`, which holds a FAKE DB password.
# PASS = the reply shows $STRIPE_KEY and $DB_PASSWORD, and neither raw value is in the reply, in any request sent
# to the model, or anywhere in opencode's storage (opencode.db, its WAL, logs, the TUI prompt history) after the run.
#   opencode/canary.sh [--no-plugin]     (--no-plugin is the mutation: it must FAIL)
# OPENCODE_BIN picks the binary (default: opencode on PATH); OC_ARGS adds run flags (e.g. --log-level DEBUG --print-logs);
# VP_KEEP=1 keeps the temp dir. On a FAIL it always lists the files that hold a raw copy (paths only, never values).
# Exit 0 = PASS.
set -u
R="$(cd "$(dirname "$0")/.." && pwd)"
OC="${OPENCODE_BIN:-opencode}"
# macOS has no `timeout` (coreutils' gtimeout if present); without either the run is simply not time-limited.
TO=(); command -v timeout >/dev/null && TO=(timeout 180) || { command -v gtimeout >/dev/null && TO=(gtimeout 180); }
# Never `kill 0`: with MP unset (an exit before the mock starts) it signals the whole process group, i.e. the caller
# too (10-08: an early refusal killed the canary and its pipeline, rc 143).
stop_mock() { [ -n "${MP:-}" ] && kill "$MP" 2>/dev/null; }
# VP_KEEP=1 keeps the temp dir (fake values only) and prints where, to see which file holds a raw copy.
drop() { if [ -n "${VP_KEEP:-}" ]; then echo "kept: $T"; else rm -rf "${T:?}"; fi; }
T=$(mktemp -d); trap 'stop_mock; drop' EXIT
mkdir -p "$T/cfg/opencode/plugins" "$T/data" "$T/state" "$T/cache" "$T/proj"
# opencode 2.x runs `run` through a managed service that outlives the run. The throwaway home gets its own service
# port, so the person's own opencode (always up on 127.0.0.1:49374 when they use 2.x) is never met; ours is stopped
# before the temp dir goes. A port already taken is refused, not shared.
# `opencode --version` prints "1.18.35" on 1.x but "opencode v2.0.22" on 2.x: compare the first number.
V2=0; [ "$("$OC" --version 2>/dev/null | grep -o '[0-9][0-9]*' | head -1)" -ge 2 ] 2>/dev/null && V2=1
if [ $V2 = 1 ]; then
  . "$R/opencode/v2svc.sh"
  v2_own_port "$OC" "$T"
  v2_foreign "$T/data" && { echo "canary: FAIL (another opencode 2.x service holds 127.0.0.1:$V2_PORT; not ours, not stopped)"; exit 1; }
  trap 'stop_mock; v2_service_stop "$OC" "$T"; drop' EXIT
fi
[ "${1:-}" = --no-plugin ] || echo "export { default } from '$R/opencode/veilpipe.ts'" > "$T/cfg/opencode/plugins/00-veilpipe.ts"
PORT=$((20000 + RANDOM % 20000))
cat > "$T/proj/opencode.json" <<EOF
{"\$schema":"https://opencode.ai/config.json","model":"mock/echo","small_model":"mock/echo","share":"disabled","autoupdate":false,
 "permission":{"bash":"allow","edit":"allow"},
 "provider":{"mock":{"npm":"@ai-sdk/openai-compatible","name":"Mock","options":{"baseURL":"http://127.0.0.1:$PORT/v1","apiKey":"not-a-key"},"models":{"echo":{"name":"echo","tool_call":true}}}}}
EOF
KEY=sk_test_DEMO0000FAKE0000FAKE0000aa; PW=FakeDbPw-0000x
printf 'STRIPE_KEY=%s\nDB_PASSWORD=%s\n' "$KEY" "$PW" > "$T/proj/secret.env"
# The TUI writes typed prompts to its history BEFORE the server sees them; `opencode run` does not, so seed it.
mkdir -p "$T/state/opencode"; printf '{"input":"my stripe key is %s","parts":[],"mode":"normal"}\n' "$KEY" > "$T/state/opencode/prompt-history.jsonl"
node "$R/opencode/mock-llm.mjs" "$PORT" "$T/requests.ndjson" & MP=$!
# Wait until the mock answers; if it never does (port clash), say so instead of a misleading "reply lacks".
up=0; for _ in $(seq 1 100); do node -e "require('http').get('http://127.0.0.1:$PORT/v1/models',()=>process.exit(0)).on('error',()=>process.exit(1))" 2>/dev/null && { up=1; break; }; sleep 0.2; done
[ $up = 1 ] || { echo "canary: FAIL (mock model did not start on 127.0.0.1:$PORT)"; exit 1; }
# The caller's OPENCODE_* settings must not leak in: OPENCODE_PURE turns every plugin off and OPENCODE_CONFIG_CONTENT
# can point the run at another model (10-06: both made this canary FAIL for reasons unrelated to veilpipe).
for v in $(compgen -e | grep '^OPENCODE_' | grep -v '^OPENCODE_BIN$'); do unset "$v"; done
( cd "$T/proj" && XDG_CONFIG_HOME="$T/cfg" XDG_DATA_HOME="$T/data" XDG_STATE_HOME="$T/state" XDG_CACHE_HOME="$T/cache" \
  ${TO[@]+"${TO[@]}"} "$OC" run --model mock/echo ${OC_ARGS:-} "my stripe key is $KEY please check RUN:cat secret.env" </dev/null > "$T/reply.txt" 2> "$T/err.txt" )
rc=$?
# opencode 2.x processes flush their log lines late (the run CLI's argv line can land after every hook, macOS 10-08);
# veilpipe's log watcher masks them within ~100 ms in the still-running service: give it a second before counting.
[ "$V2" = 1 ] && sleep 1
# awk, not wc -l: macOS wc pads its count with spaces, which broke the 0000 comparison below.
count() { grep -rao -- "$1" "${@:2}" 2>/dev/null | awk 'END{print NR}'; }
ok=1
echo "opencode $("$OC" --version 2>/dev/null) · plugin $([ "${1:-}" = --no-plugin ] && echo OFF || echo ON) · run exit $rc · requests $(awk 'END{print NR}' "$T/requests.ndjson" 2>/dev/null || echo 0)"
for v in "$KEY" "$PW"; do
  r=$(count "$v" "$T/reply.txt"); q=$(count "$v" "$T/requests.ndjson"); s=$(count "$v" "$T/data" "$T/state"); e=$(count "$v" "$T/err.txt")
  echo "  raw ${#v}-char value: reply $r · sent to model $q · storage $s · stderr/logs $e"
  [ "$r$q$s$e" = 0000 ] || ok=0
done
# On a FAIL, also show each holding line (value replaced by <RAW>, cut to 240 chars) and the file's last write relative
# to the check, so a remote report says WHICH writer and WHEN without keeping the temp dir.
END_S=$(date +%s)
mt() { stat -c %Y "$1" 2>/dev/null || stat -f %m "$1"; }
[ $ok = 1 ] || for v in "$KEY" "$PW"; do grep -rlaF -- "$v" "$T/data" "$T/state" 2>/dev/null | while read -r f; do
  echo "  raw ${#v}-char value in: ${f#"$T/"} (last write $(( $(mt "$f") - END_S ))s vs the check)"
  case "$f" in *.db|*.db-wal|*.db-shm) continue;; esac   # SQLite pages: the path is enough
  grep -aF -- "$v" "$f" | head -3 | LC_ALL=C awk -v v="$v" '{ while ((i = index($0, v)) > 0) $0 = substr($0, 1, i-1) "<RAW>" substr($0, i+length(v)); print "    line: " substr($0, 1, 240) }'
done; done
for n in STRIPE_KEY DB_PASSWORD; do grep -qF -- "\$$n" "$T/reply.txt" || { echo "  reply lacks \$$n"; ok=0; }; done
[ $rc -eq 0 ] || ok=0
[ $ok = 1 ] && echo "canary: PASS" || echo "canary: FAIL"
[ $ok = 1 ]
