// ЛР5 = ЛР4 + перевірка підпису JWT (RS256, JWKS, iss/aud/exp) + шифрування токена в JWE.
// ЛР4: token_auth (Kreolwolf1/auth_examples) переведено на Auth0.
//  - POST /api/login  → password grant до Auth0, клієнт отримує access_token + refresh_token
//  - GET  /           → з Bearer-токеном: дані користувача з /userinfo; без токена — сторінка логіну
//  - POST /api/signup → створення користувача через Management API (токен client_credentials кешується до exp)
//  - автооновлення: якщо до exp < REFRESH_THRESHOLD_SEC і клієнт передав X-Refresh-Token,
//    сервер робить refresh_token grant і повертає нові токени
const express = require('express');
const path = require('path');
const A = require('../common/auth0');
const J = require('./jwt');

const port = Number(A.E.PORT || 3000);
const THRESHOLD = Number(A.E.REFRESH_THRESHOLD_SEC || 60);
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const log = (...a) => console.log(`[${A.ts()}]`, ...a);
const bearer = (req) => (req.get('Authorization') || '').replace(/^Bearer\s+/i, '') || null;
const expOf = (t) => { try { return A.decode(t).payload.exp; } catch { return null; } };
const tokensOut = (b) => ({
  token: b.access_token, // замінюється на JWE в wrap()
  refresh_token: b.refresh_token,
  expires_in: b.expires_in,
  expires_at: expOf(b.access_token),
});

// Автооновлення токена, коли до закінчення менше THRESHOLD секунд
async function maybeRefresh(req) {
  const token = bearer(req);
  const rt = req.get('X-Refresh-Token');
  const exp = token && expOf(token);
  if (!exp || !rt) return null;
  const left = exp - Math.floor(Date.now() / 1000);
  if (left >= THRESHOLD) return null;
  log(`Токен спливає через ${left} с (< ${THRESHOLD}) → refresh_token grant`);
  const r = await A.refresh(rt);
  if (r.status !== 200) { log('Refresh не вдався:', r.status, r.body); return null; }
  const out = tokensOut(r.body);
  out.refresh_token = out.refresh_token || rt; // без rotation Auth0 повертає той самий RT не завжди
  log(`Токен оновлено: ${A.short(token)} → ${A.short(out.token)}, новий exp ${new Date(out.expires_at * 1000).toISOString()}`);
  return out;
}

// Повертаємо клієнту зашифрований JWE замість відкритого Auth0-токена
async function wrap(out) {
  if (!out) return out;
  await J.verifyAuth0(out.token); // видаємо лише перевірений токен
  return { ...out, token: await J.encrypt(out.token) };
}

app.get('/', async (req, res) => {
  let token = bearer(req);
  if (!token) return res.sendFile(path.join(__dirname, 'index.html'));

  // 1) JWE → розшифрування; 2) перевірка RS256-підпису, iss, aud, exp
  let verified;
  try {
    verified = await J.unwrapAndVerify(token);
  } catch (e) {
    log(`GET / → 401: ${e.code || ''} ${e.message}`);
    return res.status(401).json({ error: 'invalid_token', message: e.message, code: e.code });
  }
  token = verified.auth0Token;
  req.headers.authorization = `Bearer ${token}`;

  const refreshed = await wrap(await maybeRefresh(req));
  if (refreshed) token = (await J.unwrapAndVerify(refreshed.token)).auth0Token;

  const ui = await A.userinfo(token);
  if (ui.status !== 200) {
    log('GET / → 401, userinfo:', ui.status, ui.body);
    return res.status(401).json({ error: 'invalid_token', details: ui.body });
  }
  const exp = expOf(token);
  res.json({
    username: ui.body.name || ui.body.nickname || ui.body.email,
    email: ui.body.email,
    sub: ui.body.sub,
    token_expires_at: exp,
    token_expires_in: exp - Math.floor(Date.now() / 1000),
    token_format: verified.wasJwe ? 'JWE (RSA-OAEP-256 + A256GCM)' : 'JWS (RS256)',
    verified_claims: { iss: verified.payload.iss, aud: verified.payload.aud, sub: verified.payload.sub, exp: verified.payload.exp },
    refreshed,
    logout: `http://localhost:${port}/logout`,
  });
});

app.get('/logout', (req, res) => res.redirect('/'));

app.post('/api/login', async (req, res) => {
  const { login, password } = req.body;
  const r = await A.passwordLogin(login, password);
  if (r.status !== 200) {
    log(`Login ${login} → 401: ${r.body?.error_description}`);
    return res.status(401).json({ error: r.body?.error, message: r.body?.error_description });
  }
  log(`Login ${login} → OK (${r.grant}), token ${A.short(r.body.access_token)}`);
  res.json(await wrap(tokensOut(r.body)));
});

app.post('/api/refresh', async (req, res) => {
  const r = await A.refresh(req.body.refresh_token);
  if (r.status !== 200) return res.status(401).json(r.body);
  log(`Ручний refresh → ${A.short(r.body.access_token)}`);
  res.json(await wrap({ ...tokensOut(r.body), refresh_token: r.body.refresh_token || req.body.refresh_token }));
});

app.post('/api/signup', async (req, res) => {
  const { email, password, name } = req.body;
  const cc = await A.clientCredentials(); // кешується до exp
  log(`Signup ${email}: Management-токен ${cc.cached ? 'з кешу' : 'отримано новий'}, діє до ${new Date(cc.exp * 1000).toISOString()}`);
  const r = await A.mgmt('POST', '/users', { email, password, ...(name ? { name } : {}), connection: A.CONNECTION });
  log(`POST /api/v2/users ${email} → ${r.status}`);
  if (r.status !== 201) return res.status(r.status).json({ error: r.body?.error, message: r.body?.message });
  res.status(201).json({ user_id: r.body.user_id, email: r.body.email });
});

app.listen(port, () => {
  log(`ЛР5 слухає http://localhost:${port} (tenant=${A.C.name} ${A.C.domain}, refresh threshold ${THRESHOLD}s)`);
});
