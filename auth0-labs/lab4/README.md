# ЛР4 — token_auth через Auth0

База — `token_auth` з https://github.com/Kreolwolf1/auth_examples (копія в `../../lab1/token_auth`).

```bash
npm run lab4                                   # http://localhost:3000
REFRESH_THRESHOLD_SEC=86400 npm run lab4       # демо автооновлення на tenant з довгим TTL
```

| Маршрут | Що робить |
|---|---|
| `POST /api/login` `{login, password}` | password grant до Auth0 → `{access_token, refresh_token, expires_in, expires_at}` (`token` — те саме під іменем з оригіналу); помилка → 401 `{error, message}` від Auth0 |
| `GET /` + `Authorization: Bearer <token>` | дані користувача з `GET https://<domain>/userinfo`, час закінчення токена; без токена — `index.html` |
| `POST /api/signup` `{email, password}` | створення користувача через Management API, токен client_credentials кешується до `exp` |
| `POST /api/refresh` | ручний refresh |
| Автооновлення | клієнт кожні 15 с робить `GET /` з `X-Refresh-Token`; якщо до `exp` < `REFRESH_THRESHOLD_SEC`, сервер робить refresh_token grant і повертає нові токени (`refreshed`), у консолі — «Токен оновлено» |

Сценарій запитів (сервер запущено в іншому терміналі): `./lab4/requests.sh` або `./lab4/requests.sh --refresh` (чекає ~62 с і показує автооновлення; `FULL=1` — повні токени для скріншотів). Результат: `evidence/requests-own.log`, `evidence/server-own.log`.

Для демо на власному tenant: API → Settings → Token Expiration = 120 с, `REFRESH_THRESHOLD_SEC=60`.
