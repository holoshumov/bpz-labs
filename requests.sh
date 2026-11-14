#!/usr/bin/env bash
# Запити до серверу для скріншотів ЛР1. Запускати в ДРУГОМУ вікні терміналу,
# поки відповідний сервер працює в першому.
#   ./requests.sh basic | forms | token | jwt
set -u
URL=http://localhost:3000
line() { printf '\n\033[1;36m==== %s ====\033[0m\n' "$1"; }

case "${1:-}" in
basic)
  line "1. Без заголовка Authorization -> 401 + WWW-Authenticate"
  curl -i $URL/
  line "2. Невірний пароль -> 401"
  curl -i -u DateArt:wrong $URL/
  line "3. Вірні дані DateArt:2408 (Basic base64) -> 200"
  echo "Authorization: Basic $(printf 'DateArt:2408' | base64)"
  curl -i -u DateArt:2408 $URL/
  ;;
forms)
  line "1. GET / -> сервер ставить cookie session"
  curl -i -c /tmp/lab1_cookies.txt $URL/ | head -12
  line "2. POST /api/login з cookie"
  curl -i -b /tmp/lab1_cookies.txt -c /tmp/lab1_cookies.txt -H 'Content-Type: application/json' \
       -d '{"login":"Login","password":"Password"}' $URL/api/login
  line "3. GET / з тією ж cookie -> дані користувача"
  curl -i -b /tmp/lab1_cookies.txt $URL/
  line "4. Невірний пароль -> 401"
  curl -i -H 'Content-Type: application/json' -d '{"login":"Login","password":"bad"}' $URL/api/login
  ;;
token)
  line "1. POST /api/login -> token (uuid сесії)"
  RESP=$(curl -s -H 'Content-Type: application/json' -d '{"login":"Login","password":"Password"}' $URL/api/login)
  echo "$RESP"
  TOKEN=$(echo "$RESP" | sed -E 's/.*"token":"([^"]+)".*/\1/')
  line "2. GET / з Authorization: $TOKEN"
  curl -i -H "Authorization: $TOKEN" $URL/
  ;;
jwt)
  line "1. POST /api/login -> JWT"
  RESP=$(curl -s -H 'Content-Type: application/json' -d '{"login":"Login","password":"Password"}' $URL/api/login)
  echo "$RESP"
  TOKEN=$(echo "$RESP" | sed -E 's/.*"token":"([^"]+)".*/\1/')
  line "2. Розкодований payload JWT (header.payload.signature)"
  node -e "const [h,p]=process.argv[1].split('.');for(const x of [h,p])console.log(Buffer.from(x,'base64url').toString())" "$TOKEN"
  line "3. GET / з Authorization: Bearer <JWT> -> 200"
  curl -i -H "Authorization: Bearer $TOKEN" $URL/
  line "4. Підроблений payload (username=admin), старий підпис -> 401 Invalid signature"
  H=$(echo "$TOKEN" | cut -d. -f1); S=$(echo "$TOKEN" | cut -d. -f3)
  P=$(printf '{"sub":"Login","username":"admin","exp":9999999999}' | base64 | tr '+/' '-_' | tr -d '=')
  curl -i -H "Authorization: Bearer $H.$P.$S" $URL/
  ;;
*)
  echo "Використання: $0 basic|forms|token|jwt"; exit 1 ;;
esac
echo
