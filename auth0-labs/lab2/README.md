# ЛР2 — client_credentials, створення користувача, ролі

```bash
npm run lab2                      # або TENANT=kpi node lab2/run.js
node lab2/logins.js 10 5          # 10 входів, інтервал 5 хв (додаткове завдання)
nohup node lab2/logins.js 10 15 > lab2/evidence/raw/logins.out 2>&1 &   # у фоні
```

`run.js`:
1. `POST /oauth/token` `grant_type=client_credentials` (`application/x-www-form-urlencoded`) → access_token Management API, розкодування header/payload (`scope`, `exp`).
2. `POST /api/v2/users` — демо-користувач (201) і основний `TEST_USER_EMAIL` (201 або 409, якщо вже є).
3. Ролі `viewer`, `editor`, `admin`: `POST /api/v2/roles`, `POST /api/v2/users/{id}/roles`, `GET /api/v2/users/{id}/roles`.

`logins.js`: перед кожним входом змінює набір ролей користувача (DELETE + POST `/users/{id}/roles`), робить вхід password grant, пише в лог час, ролі й фрагмент токена.

Результати: `evidence/run-<tenant>.log` (кожен запис — запит + відповідь), `evidence/logins-<tenant>.log`. Перший запуск на власному tenant, де видно створення ролей (`POST /api/v2/roles`) і користувача (201): `evidence/run-own-initial.log`; при повторних запусках ролі й користувач уже існують (409 / наявні ролі).
