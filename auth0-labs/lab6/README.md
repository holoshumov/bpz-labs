# ЛР6 — вхід через сторінку SSO (Authorization Code)

Копія ЛР4 + зміни. `npm run lab6` → http://localhost:3000 → «Login через Auth0 (SSO)».

1. `GET /login` → 302 на
   `https://<domain>/authorize?client_id=…&redirect_uri=http%3A%2F%2Flocalhost%3A3000&response_type=code&response_mode=query&scope=openid%20profile%20email%20offline_access&audience=…&state=<random>&code_challenge=…&code_challenge_method=S256`.
   `state` зберігається на сервері і в HttpOnly cookie.
2. Повернення `http://localhost:3000/?code=…&state=…` → перевірка `state` (інакше 400) → `POST /oauth/token` `grant_type=authorization_code, code, redirect_uri, client_id, client_secret, code_verifier` → токени в `sessionStorage` → `GET /` показує користувача.
3. Logout → `https://<domain>/v2/logout?client_id=…&returnTo=http://localhost:3000` (на tenant викладача без `returnTo`: там localhost не в Allowed Logout URLs, Auth0 дає 400).
