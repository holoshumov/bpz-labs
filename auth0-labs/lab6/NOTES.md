# ЛР6 — нотатки

## Теорія коротко
- **Authorization Code Flow** (RFC 6749 §4.1): браузер іде на сторінку входу Auth0 (Universal Login), користувач вводить пароль там, а не в застосунку; Auth0 повертає одноразовий `code` на `redirect_uri`; сервер міняє `code` на токени з `client_secret`.
- **state** — випадкове значення проти CSRF: сервер перевіряє, що повернувся той самий state, який він видав цьому браузеру.
- **PKCE** (RFC 7636): `code_verifier` (випадковий) → `code_challenge = BASE64URL(SHA256(verifier))`; при обміні коду сервер шле verifier — перехоплений code без verifier марний.
- **SSO** — одна сесія на Auth0 для кількох застосунків; logout `/v2/logout` завершує сесію Auth0.

## Що зроблено
**Власний tenant** (`evidence/server-own.log`, `evidence/requests-own.log`) — повний цикл перевірено в браузері:
- `GET /login` → 302 на `/authorize` з усіма параметрами з умови + `state` + PKCE (`code_challenge`, S256).
- Сторінка входу Auth0 (Universal Login «Log in | BPZ Lab App») → повернення `http://localhost:3000/?code=…&state=…`.
- `state` збігся → `POST /oauth/token grant_type=authorization_code` → 200: access + refresh + id_token; сторінка показує «Hello …», email, аватар, час токена.
- Підроблений `state` → 400 «Invalid state».
- Logout → `/v2/logout?client_id=…&returnTo=http://localhost:3000` → 302 назад на localhost:3000.

**Tenant викладача** (`evidence/requests-kpi.log`): `/authorize` приймає `redirect_uri=http://localhost:3000`; `returnTo` не дозволений (400), тому там logout без `returnTo`.

## Питання до захисту
1. **Чому authorization code безпечніший за password grant?** — Застосунок не бачить пароля; вхід на сторінці Auth0 (MFA, соцмережі, SSO); токени не проходять через URL.
2. **Навіщо `state`?** — Захист від CSRF / login CSRF: прив'язує відповідь до запиту конкретного браузера.
3. **Що таке PKCE і навіщо він конфіденційному клієнту?** — Захист від перехоплення code; в OAuth 2.1 обов'язковий для всіх клієнтів.
4. **Що означає `response_mode=query`?** — `code` і `state` повертаються в query-рядку `redirect_uri`.
5. **Чому `redirect_uri` має бути в Allowed Callback URLs?** — Інакше зловмисник підставив би свій URI і отримав code; Auth0 порівнює точно.
6. **Скільки живе code?** — Одноразовий, ~10 хв (Auth0 — 10 хв); повторне використання → `invalid_grant`.
7. **Які токени повертаються?** — access_token (для API з `audience`), id_token (OIDC, дані користувача), refresh_token (бо `offline_access`).
8. **Що робить `/v2/logout`?** — Видаляє сесію Auth0 (SSO cookie) і редіректить на `returnTo` з Allowed Logout URLs.
9. **Чим `response_type=code` відрізняється від `token` (implicit)?** — Implicit віддає токен у URL-фрагменті браузеру (небезпечно, застаріло); code — лише одноразовий код.
10. **Що буде, якщо не перевіряти state?** — Атакуючий може підсунути свій code і залогінити жертву у свій акаунт.
