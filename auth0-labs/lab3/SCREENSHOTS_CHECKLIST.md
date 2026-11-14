# ЛР3 — скріншоти
1. Термінал: password grant — відповідь з `access_token`, `refresh_token`, `id_token`.
2. jwt.io: access_token і id_token (видно `sub`, `aud`, `exp`).
3. Термінал: refresh grant і блок «Порівняння iat/exp» (`changed: true`).
4. (own tenant) Термінал: `PATCH /api/v2/users/{id}` → 200.
5. (own tenant) Вхід зі старим паролем → 403 `invalid_grant`, з новим → 200.
6. Dashboard → Monitoring → Logs: «Success Exchange», «Success Change Password», «Failed Exchange».
