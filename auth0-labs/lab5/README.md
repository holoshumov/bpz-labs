# ЛР5 — перевірка підпису JWT і JWE

Копія ЛР4 + `jwt.js`.

```bash
npm run lab5            # сервер
node lab5/demo.js       # у другому терміналі: усі сценарії → evidence/demo-<tenant>.log
./lab4/requests.sh --refresh   # ті самі запити, що в ЛР4 (токен тепер JWE) + автооновлення
```

- **Перевірка підпису**: `jose.jwtVerify` з `createRemoteJWKSet(https://<domain>/.well-known/jwks.json)` — RS256 (alg з allow-list), `iss = https://<domain>/`, `aud = <API>`, `exp`.
- **JWE**: після логіну сервер видає не Auth0-токен, а JWE `alg: RSA-OAEP-256, enc: A256GCM` (ключова пара в `lab5/keys/`, у `.gitignore`). Усередині — claims і сам підписаний Auth0-токен. На вході: розшифрування → перевірка підпису.

Сценарії `demo.js`: валідний JWE (200), пошкоджений JWE (401), оригінальний JWS (200), підмінений payload (401), чужий ключ (401), `alg=none` (401), прострочений `exp` і чужа `aud` (відхилено).
