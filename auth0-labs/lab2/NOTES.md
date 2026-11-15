# ЛР2 — нотатки

## Теорія коротко
- **OAuth 2.0 Client Credentials** (RFC 6749 §4.4) — застосунок отримує токен від свого імені (без користувача): `client_id` + `client_secret` + `audience`. Використовується для machine-to-machine, зокрема для Auth0 Management API.
- **Auth0 Management API** (`https://<domain>/api/v2/`) — REST API адміністрування tenant'а; права задаються scopes (`create:users`, `read:roles` …), які видаються застосунку в Dashboard → APIs → Management API → Machine to Machine Applications.
- **Access token** — JWT (RS256): header (`alg`, `kid`), payload (`iss`, `sub`=`<client_id>@clients`, `aud`, `iat`, `exp`, `scope`, `gty=client-credentials`), підпис.
- **RBAC в Auth0** — ролі (`/api/v2/roles`) з набором permissions, призначаються користувачам (`/users/{id}/roles`).

## Що зроблено
**Tenant викладача** (`evidence/run-kpi.log`, `evidence/logins-kpi.log`):
- client_credentials → 200, `scope: "read:users create:users"`, `expires_in: 86400`.
- `POST /api/v2/users` → 201 (демо-користувач), 409 для вже наявного.
- `/api/v2/roles` → 403 `insufficient_scope` — у застосунку викладача немає прав на ролі, тому ролі зроблено на власному tenant.
- 10 входів у різний час (інтервал 5 хв) — без зміни ролей.

**Власний tenant** `dev-b5ra33c6diywgvbd.us.auth0.com` (`evidence/run-own.log`, `evidence/logins-own.log`):
- client_credentials → 200 зі scopes `read:users create:users update:users read:roles create:roles … create:role_members read:role_members`.
- `POST /api/v2/users` → 201.
- `POST /api/v2/roles` → `viewer`, `editor`, `admin`; `POST /users/{id}/roles` → 204; `GET /users/{id}/roles` → `[viewer]`.
- `logins.js 10 5` — 10 входів (password grant), усі 200, з 14.11 23:37 до 15.11 08:56 UTC (інтервал заданий 5 хв; ноутбук засинав, тому фактичні паузи від 5 хв до ~1,5 год). Перед кожним входом змінюється набір ролей: viewer → editor → admin → viewer+editor → editor+admin → viewer+admin → усі три → без ролей → admin → viewer; у лозі час, поточні ролі (`GET /users/{id}/roles`), фрагмент токена.
- Створення ролей і користувача (перший запуск): `evidence/run-own-initial.log`.

## Питання до захисту
1. **Чим client_credentials відрізняється від password grant?** — У client_credentials немає користувача: токен видається застосунку (`sub = client_id@clients`). У password grant — від імені користувача за його логіном/паролем.
2. **Навіщо `audience`?** — Вказує, для якого API видається токен; потрапляє в `aud`. API має відкидати токени з чужою `aud`.
3. **Чому `application/x-www-form-urlencoded`?** — Так вимагає RFC 6749 для token endpoint; Auth0 приймає й JSON, але стандарт — form.
4. **Що таке scope в токені Management API?** — Перелік дозволених операцій; Auth0 перевіряє його на кожному виклику (інакше 403 `insufficient_scope`, як у нас з ролями).
5. **Як розкодувати JWT?** — Розбити по `.`, base64url-декодувати першу і другу частини. Це не розшифрування: payload читає будь-хто, захищена лише цілісність (підпис).
6. **Скільки живе токен і що робити, коли сплив?** — `expires_in` (тут 86400 с). Для client_credentials refresh token не видається — просто запитати новий; токен варто кешувати до `exp`.
7. **Що повертає Auth0 при повторному створенні користувача?** — 409 Conflict «The user already exists».
8. **Що таке connection `Username-Password-Authentication`?** — Вбудована база користувачів Auth0 (database connection), де зберігаються email + хеш пароля.
9. **Як працює RBAC?** — Роль = набір permissions; користувачу призначають ролі; з увімкненим RBAC для API permissions потрапляють у токен (`permissions` claim).
10. **Де дивитися історію входів?** — Dashboard → Monitoring → Logs (події `s` — success login, `f` — failed) і User → History.
