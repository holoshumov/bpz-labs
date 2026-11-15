# Спільні функції для demo.sh і negative.sh
cd "$(dirname "$0")/.."
mkdir -p evidence
PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null || true; done; wait 2>/dev/null || true; PIDS=(); }
trap cleanup EXIT

wait_log() { # wait_log <logfile> <pattern> — чекати, доки процес не напише, що слухає порт
  for _ in $(seq 1 100); do grep -q "$2" "$1" 2>/dev/null && return 0; sleep 0.05; done
  echo "не дочекався «$2» у $1" >&2; return 1
}

start_bg() { # start_bg <logfile> <command...>
  local log=$1; shift
  _SLOG=$log
  "$@" > "$log" 2>&1 &
  PIDS+=($!)
}

stop_all() { sleep 0.4; cleanup; }

header() { printf '\n\033[1m=== %s ===\033[0m\n' "$1"; }
