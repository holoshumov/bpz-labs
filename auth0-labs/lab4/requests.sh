#!/usr/bin/env bash
# Сценарій запитів до сервера ЛР4/ЛР5 (сервер має працювати: npm run lab4 | npm run lab5).
#   ./lab4/requests.sh            — основні запити
#   ./lab4/requests.sh --refresh  — ще й чекає, поки до exp лишиться < REFRESH_THRESHOLD_SEC, і показує автооновлення
set -u
cd "$(dirname "$0")/.."; set -a; . ./.env; set +a
URL=http://localhost:${PORT:-3000}
PASS=$TEST_USER_PASSWORD; [ "${TENANT:-own}" = kpi ] && PASS=${KPI_TEST_USER_PASSWORD:-$PASS}
cut_tokens() { sed -E 's/(eyJ[A-Za-z0-9_-]{8})[A-Za-z0-9_.-]{20,}/\1...(cut)/g; s/("refresh_token":"[^"]{6})[^"]*/\1.../g'; }
[ "${FULL:-0}" = 1 ] && cut_tokens() { cat; }
field() { node -pe "JSON.parse(require('fs').readFileSync(0)).$1"; }
line() { printf '\n==== [%s] %s ====\n' "$(date -u +%FT%TZ)" "$1"; }

line "1. GET / без токена -> 200, сторінка логіну (HTML)"
curl -s -o /dev/null -w 'HTTP %{http_code}, %{content_type}\n' $URL/
line "2. POST /api/login з невірним паролем -> 401 + повідомлення Auth0"
curl -s -w '\nHTTP %{http_code}\n' -H 'Content-Type: application/json' -d "{\"login\":\"$TEST_USER_EMAIL\",\"password\":\"wrong\"}" $URL/api/login
line "3. POST /api/login -> 200: access_token, refresh_token, expires_in"
RESP=$(curl -s -H 'Content-Type: application/json' -d "{\"login\":\"$TEST_USER_EMAIL\",\"password\":\"$PASS\"}" $URL/api/login)
echo "$RESP" | cut_tokens
TOKEN=$(echo "$RESP" | field access_token); RT=$(echo "$RESP" | field refresh_token)
line "4. GET / з Authorization: Bearer <access_token> -> 200, дані користувача"
curl -s -w '\nHTTP %{http_code}\n' -H "Authorization: Bearer $TOKEN" -H "X-Refresh-Token: $RT" $URL/ | cut_tokens
line "5. GET / із зіпсованим токеном -> 401"
curl -s -w '\nHTTP %{http_code}\n' -H "Authorization: Bearer ${TOKEN%??????}AAAAAA" $URL/ | cut_tokens
line "6. POST /api/signup -> 201 (Management API, токен client_credentials)"
curl -s -w '\nHTTP %{http_code}\n' -H 'Content-Type: application/json' -d "{\"email\":\"signup-$(date +%s)@example.com\",\"password\":\"$PASS\"}" $URL/api/signup
line "7. POST /api/signup ще раз -> 201 (у консолі сервера: Management-токен з кешу)"
curl -s -w '\nHTTP %{http_code}\n' -H 'Content-Type: application/json' -d "{\"email\":\"signup2-$(date +%s)@example.com\",\"password\":\"$PASS\"}" $URL/api/signup
line "8. POST /api/signup з наявним email -> 409"
curl -s -w '\nHTTP %{http_code}\n' -H 'Content-Type: application/json' -d "{\"email\":\"$TEST_USER_EMAIL\",\"password\":\"$PASS\"}" $URL/api/signup
if [ "${1:-}" = --refresh ]; then
  EXP=$(echo "$RESP" | field expires_at); WAIT=$(( EXP - $(date +%s) - ${REFRESH_THRESHOLD_SEC:-60} + 4 ))
  line "9. Чекаємо ${WAIT} с, поки до exp лишиться < ${REFRESH_THRESHOLD_SEC:-60} с"
  [ "$WAIT" -gt 0 ] && sleep "$WAIT"
  line "10. GET / зі старим токеном + X-Refresh-Token -> сервер оновлює токен (поле refreshed)"
  curl -s -w '\nHTTP %{http_code}\n' -H "Authorization: Bearer $TOKEN" -H "X-Refresh-Token: $RT" $URL/ | cut_tokens
fi
echo
