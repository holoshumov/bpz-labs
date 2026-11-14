#!/bin/zsh
# Записує Client ID і Client Secret застосунку M2M у auth0-labs/.env (секрет не відображається).
ENV_FILE="${0:A:h}/../.env"
read "cid?Client ID: "
read -s "csec?Client Secret (не відображається): "; echo
for kv in "AUTH0_CLIENT_ID=$cid" "AUTH0_CLIENT_SECRET=$csec"; do
  key="${kv%%=*}"
  grep -v "^$key=" "$ENV_FILE" > "$ENV_FILE.tmp" && mv "$ENV_FILE.tmp" "$ENV_FILE"
  print -r -- "$kv" >> "$ENV_FILE"
done
chmod 600 "$ENV_FILE"; echo "Готово: Client ID і Secret записано"
