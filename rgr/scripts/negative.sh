#!/usr/bin/env bash
# Негативні сценарії з логами в evidence/:
#  neg1-keyswap       MITM підміняє публічний ключ → finished не сходиться → розрив
#  neg1b-keyswap-cert MITM підміняє ключ, сертифікат лишає → клієнт відхиляє на кроці 2 (бонус X.509)
#  neg2-tamper        MITM змінює 1 байт шифротексту → AES-GCM: unable to authenticate data
#  neg3-replay        MITM повторює повідомлення → відхилено за seq
#  neg4-bad-finished  клієнт надсилає невірний finished → рукостискання не завершується
set -euo pipefail
source "$(dirname "$0")/common.sh"
PORT=${PORT:-8443}
MITM_PORT=${MITM_PORT:-9443}

via_mitm() { # via_mitm <name> <mode> <server args...>
  local name=$1 mode=$2; shift 2
  header "$name"
  start_bg "evidence/$name-server.log" node server.js --port "$PORT" "$@"
  wait_log "$_SLOG" "слухаю"
  start_bg "evidence/$name-mitm.log" node mitm.js --mode "$mode" --listen "$MITM_PORT" --target "127.0.0.1:$PORT"
  wait_log "evidence/$name-mitm.log" "слухає"
  set +e
  printf 'Перше повідомлення: переказати 100 грн\nДруге повідомлення\n' | node client.js --port "$MITM_PORT" > "evidence/$name-client.log" 2>&1
  echo "  код виходу клієнта: $? (очікувано 1)"
  set -e
  stop_all
  grep -h '✘' "evidence/$name-"*.log | sed 's/^/  /'
}

rm -f evidence/neg*.log
[ -f keys/server.crt ] || bash scripts/gen-cert.sh > /dev/null

via_mitm neg1-keyswap keyswap --no-cert
via_mitm neg1b-keyswap-cert keyswap-cert
via_mitm neg2-tamper tamper --no-cert
via_mitm neg3-replay replay --no-cert

header neg4-bad-finished
start_bg evidence/neg4-bad-finished-server.log node server.js --port "$PORT" --no-cert
wait_log "$_SLOG" "слухаю"
set +e
printf 'не має дійти\n' | node client.js --port "$PORT" --bad-finished > evidence/neg4-bad-finished-client.log 2>&1
echo "  код виходу клієнта: $? (очікувано 1)"
set -e
stop_all
grep -h '✘' evidence/neg4-bad-finished-*.log | sed 's/^/  /'

header "Готово: логи в evidence/neg*.log"
ls -1 evidence/neg*.log
