# ЛР3 — password grant, refresh token, зміна пароля

```bash
npm run lab3           # або TENANT=kpi node lab3/run.js
```
1. `POST /oauth/token` `grant_type=password` (`username`, `password`, `audience`, `scope=openid profile email offline_access`, `client_id`, `client_secret`) → `access_token` + `refresh_token` + `id_token`. На tenant викладача (без Default Directory) автоматично використовується `grant_type=http://auth0.com/oauth/grant-type/password-realm` з `realm=Username-Password-Authentication`.
2. `grant_type=refresh_token` → новий access_token; лог порівнює `iat`/`exp` старого й нового.
3. `PATCH /api/v2/users/{id}` `{password, connection}` з токеном **client_credentials** → вхід зі старим паролем (403 `invalid_grant`) і з новим (200). Після успіху скрипт міняє місцями `TEST_USER_PASSWORD`/`TEST_USER_NEW_PASSWORD` у `.env`, щоб його можна було запускати знову.

Результат: `evidence/run-<tenant>.log`.
