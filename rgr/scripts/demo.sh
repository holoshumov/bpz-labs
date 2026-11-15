#!/usr/bin/env bash
# Автоматичне демо: сервер + клієнт + чат + файл. Логи обох сторін → evidence/.
#  1) demo-basic   — базовий варіант (сервер генерує RSA-пару, надсилає лише public key)
#  2) demo-cert    — бонус: сервер надсилає самопідписаний X.509, клієнт перевіряє відповідність ключа
#  3) demo-multi   — два клієнти одночасно, кожен зі своїм сеансом і своїми ключами
#  4) demo-verbose — повні значення random/premaster/ключів (--verbose)
set -euo pipefail
source "$(dirname "$0")/common.sh"
PORT=${PORT:-8443}

chat_input() {
  printf '%s\n' \
    "Привіт, сервере! Це захищений чат ІМ-31." \
    "Друге повідомлення: AES-256-GCM, nonce = IV xor seq" \
    "/send samples/message.txt"
}

run_pair() { # run_pair <name> <server args...>
  local name=$1; shift
  header "$name"
  start_bg "evidence/$name-server.log" node server.js --port "$PORT" "$@"
  wait_log "$_SLOG" "слухаю"
  chat_input | node client.js --port "$PORT" ${CLIENT_ARGS:-} > "evidence/$name-client.log" 2>&1
  stop_all
  check_keys "$name"
}

# Перевірка: master і ключі сеансу в логах клієнта й сервера однакові
check_keys() {
  local name=$1 ok=1
  for k in master client_write_key server_write_key client_iv server_iv; do
    local c s
    c=$(grep -m1 " $k " "evidence/$name-client.log" | awk '{print $2}')
    s=$(grep -m1 " $k " "evidence/$name-server.log" | awk '{print $2}')
    if [ -n "$c" ] && [ "$c" = "$s" ]; then echo "  ✔ $k однаковий: $c"; else echo "  ✘ $k: клієнт=$c сервер=$s"; ok=0; fi
  done
  local hc hs
  hc=$(grep -m1 'sha256  ' "evidence/$name-client.log" | awk '{print $2}')
  hs=$(grep -m1 'sha256 обчислений' "evidence/$name-server.log" | awk '{print $3}')
  [ -n "$hc" ] && [ "$hc" = "$hs" ] && echo "  ✔ SHA-256 файлу однаковий: $hc" || { echo "  ✘ SHA-256 файлу: $hc / $hs"; ok=0; }
  grep -q 'усі повідомлення підтверджено' "evidence/$name-client.log" && echo "  ✔ чат: усі повідомлення підтверджено сервером" || ok=0
  [ $ok = 1 ] || { echo "ПОМИЛКА в $name"; exit 1; }
}

rm -f evidence/demo-*.log
[ -f keys/server.crt ] || bash scripts/gen-cert.sh > /dev/null

run_pair demo-basic --no-cert
run_pair demo-cert

header demo-multi
start_bg evidence/demo-multi-server.log node server.js --port "$PORT" --no-cert
wait_log "$_SLOG" "слухаю"
printf 'Я клієнт A\n' | node client.js --port "$PORT" > evidence/demo-multi-client-A.log 2>&1 &
A=$!
printf 'Я клієнт B\n/send samples/message.txt\n' | node client.js --port "$PORT" > evidence/demo-multi-client-B.log 2>&1 &
B=$!
wait $A $B
stop_all
ma=$(grep -m1 ' master ' evidence/demo-multi-client-A.log | awk '{print $2}')
mb=$(grep -m1 ' master ' evidence/demo-multi-client-B.log | awk '{print $2}')
echo "  сеанси на сервері: $(grep -c 'КРОК 7/7' evidence/demo-multi-server.log)"
[ "$ma" != "$mb" ] && echo "  ✔ у клієнтів A і B різні master: $ma ≠ $mb" || { echo "  ✘ однакові master"; exit 1; }

CLIENT_ARGS=--verbose run_pair demo-verbose --no-cert --verbose

header "Готово: логи в evidence/demo-*.log"
ls -1 evidence/demo-*.log
