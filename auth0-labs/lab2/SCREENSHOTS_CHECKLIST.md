# ЛР2 — скріншоти (знімає студент)
1. Термінал: `node lab2/run.js` — запит client_credentials і відповідь з токеном (повний токен — у `evidence/raw/run-*.log`).
2. jwt.io: вставлений access_token, видно `scope`, `exp`, `aud`.
3. Термінал: `POST /api/v2/users` → 201 (і 409 для повторного).
4. Auth0 Dashboard → User Management → Users: створений користувач.
5. (own tenant) Dashboard → User Management → Roles: `viewer`, `editor`, `admin`; користувач → вкладка Roles.
6. `evidence/logins-*.log` — 10 входів з різним часом і ролями.
7. (own tenant) Dashboard → Monitoring → Logs: 10 подій «Success Exchange» у різний час.
8. (own tenant) Dashboard → Users → користувач → History.
