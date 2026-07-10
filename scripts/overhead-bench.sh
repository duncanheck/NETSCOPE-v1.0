#!/usr/bin/env bash
# NETSCOPE agent overhead benchmark (ROADMAP A6).
#
# Measures the agent's steady-state cost — CPU (% of one core) and peak RSS — under
# three pinned, self-contained load scenarios, so the numbers are reproducible
# rather than "fast on my machine that day" (PITFALLS A6). No external network: a
# local TCP sink and a load generator create the connections the agent captures.
#
#   idle    : the agent's ambient cost (just the box's own connections)
#   browse  : ~60 held connections with light churn (a browsing session)
#   churn   : ~250 held + a high open/close rate (torrent-level churn)
#
# The dominant cost is the 250 ms capture poll: reading /proc/net/* and sweeping
# /proc/*/fd to map sockets to PIDs — so cost scales with connection count AND the
# number of processes on the host. The environment header records both.
#
# Usage:  scripts/overhead-bench.sh
set -euo pipefail

PORT=18900
WARMUP=3        # seconds discarded before sampling
WINDOW=15       # seconds sampled per scenario
AGENT_BIN="agent/target/release/netscope-agent"
TMP="$(mktemp -d)"
PIDS=()

ulimit -n 8192 2>/dev/null || true   # headroom for the churn scenario's sockets

cleanup() {
  for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done
  rm -rf "$TMP"
}
trap cleanup EXIT

# --- build -------------------------------------------------------------------
echo "building agent (release)…"
(cd agent && cargo build --release -p netscope-agent >/dev/null 2>&1)

# --- local TCP sink: accept and hold connections -----------------------------
cat > "$TMP/sink.py" <<'PY'
import socket, sys
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", int(sys.argv[1])))
s.listen(4096)
CAP = 400              # hold at most this many; close oldest beyond it so the
held = []              # sink doesn't leak fds when the client side churns
while True:
    try:
        c, _ = s.accept()
    except OSError:
        continue
    held.append(c)
    while len(held) > CAP:
        held.pop(0).close()
PY
python3 "$TMP/sink.py" "$PORT" & PIDS+=($!)

# --- load generators ---------------------------------------------------------
cat > "$TMP/browse.py" <<'PY'
import socket, sys, time
port, target = int(sys.argv[1]), int(sys.argv[2])
conns = []
def opn():
    try:
        c = socket.socket(); c.connect(("127.0.0.1", port)); conns.append(c)
    except OSError:
        pass
for _ in range(target):
    opn()
while True:
    time.sleep(0.5)
    for _ in range(5):              # light churn: close 5, open 5
        if conns: conns.pop(0).close()
        opn()
PY

cat > "$TMP/churn.py" <<'PY'
import socket, sys, time
port = int(sys.argv[1])
conns = []
while True:
    for _ in range(40):            # ~800 opens/sec
        try:
            c = socket.socket(); c.connect(("127.0.0.1", port)); conns.append(c)
        except OSError:
            pass
    while len(conns) > 250:        # keep them short-lived
        conns.pop(0).close()
    time.sleep(0.05)
PY

# --- start the agent + a draining WebSocket client ---------------------------
RUST_LOG=error "$AGENT_BIN" >/dev/null 2>&1 & AGENT=$!; PIDS+=($AGENT)
sleep 1
if ! kill -0 "$AGENT" 2>/dev/null; then echo "agent failed to start"; exit 1; fi

CLIENT_NOTE="with 1 draining client"
if command -v node >/dev/null 2>&1; then
  node -e 'const w=new WebSocket("ws://127.0.0.1:8787/ws");w.onmessage=()=>{};w.onerror=()=>{};setInterval(()=>{},1e9);' \
    >/dev/null 2>&1 & PIDS+=($!)
else
  CLIENT_NOTE="capture-only (no node client)"
fi
sleep 1

# --- sampler: echo "<cpu%> <peakRSS_MB>" over WINDOW seconds ------------------
port_hex=$(printf '%04X' "$PORT")
sample() {
  local pid=$1
  read -r u0 s0 < <(awk '{print $14, $15}' "/proc/$pid/stat")
  local start; start=$(date +%s%3N)
  local peak=0 rss
  for ((i = 0; i < WINDOW; i++)); do
    rss=$(awk '/^VmRSS/{print $2}' "/proc/$pid/status" 2>/dev/null || echo 0)
    ((rss > peak)) && peak=$rss
    sleep 1
  done
  read -r u1 s1 < <(awk '{print $14, $15}' "/proc/$pid/stat")
  local end; end=$(date +%s%3N)
  awk -v du=$((u1 - u0)) -v ds=$((s1 - s0)) -v clk="$(getconf CLK_TCK)" \
      -v ms=$((end - start)) -v peak="$peak" \
      'BEGIN { secs = ms/1000.0; printf "%.2f %.1f", ((du+ds)/clk)/secs*100, peak/1024.0 }'
}

count_conns() { grep -ic ":$port_hex " /proc/net/tcp 2>/dev/null || echo 0; }

run() {
  local name=$1 script=${2:-} arg=${3:-}
  local load=""
  if [[ -n $script ]]; then python3 "$script" "$PORT" $arg & load=$!; PIDS+=($load); fi
  sleep "$WARMUP"
  local conns; conns=$(count_conns)
  local res; res=$(sample "$AGENT")
  [[ -n $load ]] && { kill "$load" 2>/dev/null || true; wait "$load" 2>/dev/null || true; }
  printf '%-8s %8s %12s %12s\n' "$name" "$conns" "$(echo "$res" | cut -d' ' -f1)" "$(echo "$res" | cut -d' ' -f2)"
}

# --- environment header ------------------------------------------------------
echo
echo "=== environment ==="
echo "cpu      : $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | sed 's/^ //')"
echo "cores    : $(nproc)   kernel: $(uname -r)"
echo "processes: $(find /proc -maxdepth 1 -regex '/proc/[0-9]+' | wc -l)   (drives the inode→pid sweep cost)"
echo "agent    : netscope-agent $(grep -m1 'version' agent/Cargo.toml | sed -E 's/.*"([0-9.]+)".*/\1/') (release)"
echo "sampling : ${WARMUP}s warmup + ${WINDOW}s window, $CLIENT_NOTE"
echo
printf '%-8s %8s %12s %12s\n' "scenario" "tcp(/2)" "cpu %1core" "peakRSS MB"
echo "------------------------------------------------"
run idle
run browse "$TMP/browse.py" 60
run churn  "$TMP/churn.py"
echo "------------------------------------------------"
echo "(tcp column counts /proc/net/tcp rows for the sink port; ~2× the connection count, both ends being local)"
