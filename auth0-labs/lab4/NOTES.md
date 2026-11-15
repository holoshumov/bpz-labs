# ЛР4 — нотатки

## Теорія коротко
- У базовому `token_auth` токен — випадковий UUID сесії, що зберігається в `sessions.json`. Тут замість нього — **access_token від Auth0** (Bearer, RFC 6750), сервер не зберігає сесій.
- Перевірка токена — через `GET /userinfo` (Auth0 сам перевіряє токен). Локальна перевірка підпису — ЛР5.
- Реєстрація — через Management API з токеном client_credentials, кешованим до `exp`.
- Термін життя: `exp` у payload; якщо до кінця < N с — refresh_token grant.

## Що зроблено
**Власний tenant** (`evidence/server-own.log`), TTL API = 120 с, `REFRESH_THRESHOLD_SEC=60`:
- `POST /api/login` → 200 (`expires_in: 120`), невірний пароль → 401 «Wrong email or password.».
- `GET /` з Bearer → 200 (username, email, sub, час закінчення токена); без токена — сторінка логіну.
- `POST /api/signup` → 201 (Management-токен client_credentials, кешується до `exp`).
- Автооновлення: через 64 с після входу — «Токен спливає через 56 с (< 60) → refresh_token grant», «Токен оновлено: … новий exp …».

**Tenant викладача** (`evidence/requests-kpi.log`, `evidence/server-refresh-demo.log`) — те саме, демо автооновлення з `REFRESH_THRESHOLD_SEC=86400` (TTL там 24 год).

## Питання до захисту
1. **Що таке Bearer-токен?** — Токен «на пред'явника» (RFC 6750): хто має — той і авторизований. Передається в `Authorization: Bearer …`, тільки по HTTPS.
2. **Чим відрізняється від сесійного токена ЛР1?** — Сесійний — випадковий ідентифікатор, стан на сервері. JWT від Auth0 — самодостатній, містить claims і підпис, сервер може не зберігати стан.
3. **Як сервер дізнається користувача?** — `GET /userinfo` з тим самим токеном (потрібен scope `openid`) або з payload токена (`sub`).
4. **Чому реєстрація йде через сервер?** — Потрібен Management-токен із `create:users`; client_secret не можна віддавати в браузер.
5. **Навіщо кешувати Management-токен?** — Ліміти Auth0 на видачу M2M-токенів, швидкість; кеш до `exp - 60 с`.
6. **Як працює автооновлення?** — Клієнт періодично надсилає токен + refresh_token; сервер порівнює `exp - now` з N і за потреби робить refresh_token grant.
7. **Де зберігати токени в браузері?** — Тут `sessionStorage` (як у базовому прикладі). Безпечніше — HttpOnly Secure cookie (захист від XSS).
8. **Що повертається при невірному паролі?** — Auth0 `403 invalid_grant` → наш сервер `401` з `message` від Auth0.
9. **Чому `expires_at`, а не тільки `expires_in`?** — `expires_in` відносний; клієнту зручніше абсолютний час для показу і перевірки.
10. **Що робить logout?** — Видаляє токени з `sessionStorage`; токен Auth0 живе до `exp` (stateless), тому TTL має бути коротким.
