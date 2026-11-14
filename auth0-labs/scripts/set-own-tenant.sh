#!/bin/zsh
# Записує дані власного Auth0 tenant'а в auth0-labs/.env (секрет не відображається при введенні).
ENV_FILE="${0:A:h}/../.env"
read "domain?Domain (напр. dev-xxxx.eu.auth0.com): "
domain="${domain#https://}"; domain="${domain%/}"
read "cid?Client ID: "
read -s "csec?Client Secret (не відображається): "; echo
for kv in "AUTH0_DOMAIN=$domain" "AUTH0_CLIENT_ID=$cid" "AUTH0_CLIENT_SECRET=$csec" "AUTH0_MGMT_AUDIENCE=https://$domain/api/v2/"; do
  key="${kv%%=*}"
  grep -v "^$key=" "$ENV_FILE" > "$ENV_FILE.tmp" && mv "$ENV_FILE.tmp" "$ENV_FILE"
  print -r -- "$kv" >> "$ENV_FILE"
done
chmod 600 "$ENV_FILE"
echo "Готово: .env оновлено для $domain"
