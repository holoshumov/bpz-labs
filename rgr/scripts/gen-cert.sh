#!/usr/bin/env bash
# Бонус: самопідписаний X.509-сертифікат сервера (RSA-2048, SHA-256, SAN localhost/127.0.0.1).
# Результат: keys/server.key (приватний ключ, у .gitignore) і keys/server.crt.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p keys
openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 365 \
  -keyout keys/server.key -out keys/server.crt \
  -subj "/C=UA/ST=Kyiv/L=Kyiv/O=KPI/OU=IM-31 Holoshumov/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null
chmod 600 keys/server.key
openssl x509 -in keys/server.crt -noout -subject -issuer -dates -fingerprint -sha256
