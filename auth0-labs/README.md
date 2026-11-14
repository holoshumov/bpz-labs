# БПЗ 2026 — ЛР2–ЛР6 (Auth0)

Голошумов В. М., ІМ-31. Node.js 18+ (перевірено на v24), Express, `jose`.

```bash
cd auth0-labs
npm install
cp .env.example .env   # заповнити (див. нижче)
```

## Tenant
Усі скрипти працюють з двома tenant'ами (`common/auth0.js`):

| `TENANT` | Що використовується | Коли |
|---|---|---|
| `own` | `AUTH0_*` — власний tenant | за замовчуванням, якщо `AUTH0_DOMAIN` заповнено |
| `kpi` | `KPI_*` — tenant викладача `kpi.eu.auth0.com` | якщо `AUTH0_DOMAIN` порожній, або явно `TENANT=kpi` |

Приклад: `TENANT=kpi node lab2/run.js`.

Можливості tenant викладача (перевірено 14.11.2026):

| Операція | kpi | own |
|---|---|---|
| client_credentials → Management API (`read:users create:users`) | ✅ | ✅ |
| `POST /api/v2/users` | ✅ 201 | ✅ |
| `/api/v2/roles` (ролі) | ❌ 403 `insufficient_scope` | ✅ |
| `PATCH /api/v2/users/{id}` (зміна пароля) | ❌ 403 `insufficient_scope` | ✅ |
| `grant_type=password` | ❌ «not configured with default connection» → автоматично `password-realm` | ✅ |
| refresh_token | ✅ | ✅ |
| `/authorize` з `redirect_uri=http://localhost:3000` | ✅ | ✅ |
| `/v2/logout` з `returnTo=http://localhost:3000` | ❌ 400 (не в Allowed Logout URLs) → без `returnTo` | ✅ |

## Лабораторні
| ЛР | Запуск | Що робить |
|---|---|---|
| ЛР2 | `npm run lab2`, `node lab2/logins.js 10 5` | client_credentials, створення користувача, ролі, 10 входів |
| ЛР3 | `npm run lab3` | password grant, refresh, зміна пароля |
| ЛР4 | `npm run lab4` → http://localhost:3000 | token_auth через Auth0, реєстрація, автооновлення токена |
| ЛР5 | `npm run lab5`, `node lab5/demo.js` | перевірка RS256 (JWKS, iss/aud/exp), JWE |
| ЛР6 | `npm run lab6` → http://localhost:3000 | SSO, authorization code + state + PKCE, logout |

У кожній папці: `README.md`, `NOTES.md` (теорія, що зроблено, питання до захисту), `SCREENSHOTS_CHECKLIST.md`, `evidence/`.

`evidence/*.log` — з обрізаними токенами (в git). `evidence/raw/*.log` — повні токени для скріншотів (у `.gitignore`).
