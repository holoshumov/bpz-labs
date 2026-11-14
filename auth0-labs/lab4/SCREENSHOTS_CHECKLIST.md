# ЛР4 — скріншоти
1. Браузер http://localhost:3000 — форма логіну + форма реєстрації.
2. Невдалий вхід — повідомлення «Wrong email or password.»; DevTools → Network → `/api/login` 401.
3. Успішний вхід — «Hello …», час закінчення токена; DevTools → Network → `/api/login` (відповідь з токеном) і `GET /` з заголовком `Authorization: Bearer …`.
4. Реєстрація — «Створено …»; Dashboard → Users — новий користувач.
5. Автооновлення: (own tenant, TTL 120 с, N=60) консоль сервера з «Токен оновлено», DevTools → Network → відповідь `GET /` з `refreshed`.
