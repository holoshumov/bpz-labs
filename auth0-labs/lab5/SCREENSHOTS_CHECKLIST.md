# ЛР5 — скріншоти
1. Браузер https://<domain>/.well-known/jwks.json (і/або `/pem`) — публічні ключі, `kid`.
2. Термінал: `node lab5/demo.js` — усі сценарії (200 / 401).
3. Консоль сервера `evidence/server.log` — коди помилок `ERR_JWS_SIGNATURE_VERIFICATION_FAILED`, `ERR_JOSE_ALG_NOT_ALLOWED`, `ERR_JWE_DECRYPTION_FAILED`.
4. jwt.io: Auth0 JWS — payload видно; підмінений токен — «Invalid Signature» (вставити публічний ключ з `/pem`).
5. jwt.io: JWE з `evidence/raw/demo-*.log` — не розкодовується.
6. Браузер http://localhost:3000 після входу — «Формат токена: JWE»; DevTools → Network → `/api/login` — токен з 5 частин.
