# ЛР3 — нотатки

## Теорія коротко
- **Resource Owner Password Credentials** (RFC 6749 §4.3) — застосунок сам приймає логін/пароль і міняє їх на токени. Лише для довірених (first-party) застосунків; в OAuth 2.1 вилучено.
- В Auth0 password grant потребує **Default Directory** (Tenant Settings → API Authorization Settings) або розширення `password-realm` з явним `realm`.
- `offline_access` у scope + «Allow Offline Access» в API → видається **refresh_token**.
- **Refresh token grant** — новий access_token без повторного введення пароля; `iat`/`exp` нові.
- **id_token** — JWT OpenID Connect з даними користувача (`email`, `name`, `aud = client_id`).

## Що зроблено
**Власний tenant** (`evidence/run-own.log`) — усе за умовою:
- `grant_type=password`, `audience=https://bpz-lab-api` → 200: access_token + refresh_token + id_token.
- `grant_type=refresh_token` → 200, `iat`/`exp` нового токена інші (`changed: true`).
- `PATCH /api/v2/users/{id}` `{password, connection}` з токеном client_credentials → 200.
- Вхід зі старим паролем → 403 `invalid_grant` «Wrong email or password.»; з новим → 200.

**Tenant викладача** (`evidence/run-kpi.log`): password grant лише через `password-realm` (Default Directory не задано), refresh → 200, зміна пароля → 403 (немає `update:users`).

## Питання до захисту
1. **Чому password grant вважається небезпечним?** — Застосунок бачить пароль користувача; немає MFA/SSO-сторінки; в OAuth 2.1 його прибрали. Замість нього — authorization code + PKCE (ЛР6).
2. **Що таке Default Directory і чому без нього помилка?** — Connection, у якій Auth0 шукає користувача для password grant. Без неї — «not configured with default connection»; рішення — задати її або `password-realm` з `realm`.
3. **Як отримати refresh token?** — `scope` містить `offline_access`, API має «Allow Offline Access», у застосунку ввімкнено grant «Refresh Token».
4. **Чим access_token відрізняється від id_token?** — access_token — для API (`aud` = API); id_token — для клієнта, підтвердження автентифікації (`aud` = client_id), не можна слати в API.
5. **Що змінюється після refresh?** — Новий access_token з новими `iat`/`exp` (і `jti`); refresh token той самий або новий (при rotation).
6. **Чому пароль міняємо токеном client_credentials, а не токеном користувача?** — `PATCH /api/v2/users/{id}` — Management API, потрібен scope `update:users`, який має застосунок, а не користувач.
7. **Що буде з refresh token після зміни пароля?** — Auth0 може відкликати сесії; старий пароль більше не дає токен (`invalid_grant: Wrong email or password`).
8. **Як захистити refresh token?** — Зберігати лише на сервері / в HttpOnly cookie, rotation + reuse detection, обмежений термін.
9. **Що таке `invalid_grant`?** — Код помилки RFC 6749: невірні облікові дані, прострочений/відкликаний код або refresh token.
10. **Які вимоги до пароля в Auth0?** — Password Policy connection'а (за замовчуванням «Good»: 8+ символів, 3 з 4 типів).
