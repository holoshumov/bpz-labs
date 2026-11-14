# ЛР6 — скріншоти
1. http://localhost:3000 — кнопка «Login через Auth0 (SSO)».
2. DevTools → Network: `GET /login` 302 → `Location: https://<domain>/authorize?...` (видно всі параметри, state, code_challenge).
3. Сторінка входу Auth0 (Universal Login) — увійти тестовим користувачем (`TEST_USER_EMAIL` / пароль з `.env`).
4. Адреса `http://localhost:3000/?code=...&state=...` (DevTools → Network, перший запит після редіректу).
5. Консоль сервера: «POST /oauth/token grant_type=authorization_code → 200», «Отримано токени».
6. Сторінка з даними користувача (Hello …, email, час токена).
7. Logout → редірект через `/v2/logout` назад на localhost:3000.
8. http://localhost:3000/?code=x&state=forged → «Invalid state» (400).
9. Dashboard → Monitoring → Logs: «Success Login», «Success Exchange» (authorization code), «Success Logout».
