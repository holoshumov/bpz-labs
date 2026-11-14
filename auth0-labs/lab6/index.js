// ЛР6 = ЛР4 + вхід через сторінку SSO Auth0 (Authorization Code Flow + state + PKCE S256).
//  GET /login        → редірект на https://<domain>/authorize?...&response_type=code&state=...&code_challenge=...
//  GET /?code&state  → перевірка state, обмін коду: POST /oauth/token grant_type=authorization_code
//  GET /logout       → https://<domain>/v2/logout?client_id=...&returnTo=http://localhost:3000
const express = require('express');
const path = require('path');
const crypto = require('crypto');
const A = require('../common/auth0');

const port = Number(A.E.PORT || 3000);
const THRESHOLD = Number(A.E.REFRESH_THRESHOLD_SEC || 60);
const REDIRECT_URI = `http://localhost:${port}`;
const app = express();
app.use(express.json());

const log = (...a) => console.log(`[${A.ts()}]`, ...a);
const bearer = (req) => (req.get('Authorization') || '').replace(/^Bearer\s+/i, '') || null;
const expOf = (t) => { try { return A.decode(t).payload.exp; } catch { return null; } };
const cookies = (req) => Object.fromEntries((req.get('cookie') || '').split(';').filter(Boolean)
  .map((c) => c.trim().split('=').map(decodeURIComponent)));
const tokensOut = (b) => ({
  token: b.access_token, refresh_token: b.refresh_token, id_token: b.id_token,
  expires_in: b.expires_in, expires_at: expOf(b.access_token),
});

// state → { verifier, created } ; живе 10 хв
const pending = new Map();
setInterval(() => { const t = Date.now(); for (const [k, v] of pending) if (t - v.created > 600_000) pending.delete(k); }, 60_000).unref();

app.get('/login', (req, res) => {
  const state = crypto.randomBytes(16).toString('base64url');
  const verifier = crypto.randomBytes(32).toString('base64url');                       // PKCE
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  pending.set(state, { verifier, created: Date.now() });
  const url = new URL(`https://${A.C.domain}/authorize`);
  url.search = new URLSearchParams({
    client_id: A.C.clientId,
    redirect_uri: REDIRECT_URI,
    response_type: 'code',
    response_mode: 'query',
    scope: 'openid profile email offline_access',
    audience: A.C.audience,
    state,
    code_challenge: challenge,
    code_challenge_method: 'S256',
  }).toString();
  // state також прив'язуємо до браузера cookie (захист від CSRF / підкидання чужого code)
  res.setHeader('Set-Cookie', `oauth_state=${state}; HttpOnly; SameSite=Lax; Path=/; Max-Age=600`);
  log(`GET /login → 302 ${url.toString().replace(/state=[^&]+/, 'state=…').replace(/code_challenge=[^&]+/, 'code_challenge=…')}`);
  res.redirect(url.toString());
});

async function handleCallback(req, res) {
  const { code, state, error, error_description } = req.query;
  if (error) {
    log(`Callback з помилкою: ${error} ${error_description}`);
    return res.status(400).send(`Auth0 error: ${error} — ${error_description}. <a href="/">Назад</a>`);
  }
  const p = pending.get(state);
  if (!state || !p || cookies(req).oauth_state !== state) {
    log(`Callback: state не збігається → 400 (state=${A.short(state)})`);
    return res.status(400).send('Invalid state. <a href="/">Назад</a>');
  }
  pending.delete(state);
  const r = await A.authCode(code, REDIRECT_URI, p.verifier);
  log(`POST /oauth/token grant_type=authorization_code code=${A.short(code)} → ${r.status}`);
  if (r.status !== 200) return res.status(401).send(`Token exchange failed: ${JSON.stringify(r.body)}`);
  log(`Отримано токени: access ${A.short(r.body.access_token)}, refresh ${r.body.refresh_token ? 'так' : 'ні'}, id_token ${r.body.id_token ? 'так' : 'ні'}`);
  // Токени передаються сторінці, яка кладе їх у sessionStorage і прибирає ?code з адреси
  res.setHeader('Set-Cookie', 'oauth_state=; Path=/; Max-Age=0');
  res.send(`<!doctype html><meta charset="utf-8"><script>
    sessionStorage.setItem('session', ${JSON.stringify(JSON.stringify(tokensOut(r.body)))});
    location.replace('/');
  </script>`);
}

async function maybeRefresh(req) {
  const token = bearer(req);
  const rt = req.get('X-Refresh-Token');
  const exp = token && expOf(token);
  if (!exp || !rt) return null;
  const left = exp - Math.floor(Date.now() / 1000);
  if (left >= THRESHOLD) return null;
  log(`Токен спливає через ${left} с (< ${THRESHOLD}) → refresh_token grant`);
  const r = await A.refresh(rt);
  if (r.status !== 200) return null;
  const out = tokensOut(r.body);
  out.refresh_token = out.refresh_token || rt;
  log(`Токен оновлено, новий exp ${new Date(out.expires_at * 1000).toISOString()}`);
  return out;
}

app.get('/', async (req, res) => {
  if (req.query.code || req.query.error) return handleCallback(req, res);
  let token = bearer(req);
  if (!token) return res.sendFile(path.join(__dirname, 'index.html'));
  const refreshed = await maybeRefresh(req);
  if (refreshed) token = refreshed.token;
  const ui = await A.userinfo(token);
  if (ui.status !== 200) return res.status(401).json({ error: 'invalid_token', details: ui.body });
  const exp = expOf(token);
  res.json({
    username: ui.body.name || ui.body.nickname || ui.body.email,
    email: ui.body.email, sub: ui.body.sub, picture: ui.body.picture,
    token_expires_at: exp, token_expires_in: exp - Math.floor(Date.now() / 1000),
    refreshed,
  });
});

app.get('/logout', (req, res) => {
  // На tenant викладача localhost:3000 не внесено в Allowed Logout URLs (Auth0 відповідає 400),
  // тому там returnTo не передаємо — Auth0 сам повертає на першу Callback URL застосунку (localhost:3000).
  const withReturn = A.C.name === 'own' || A.E.LOGOUT_RETURN_TO === '1';
  const url = `https://${A.C.domain}/v2/logout?client_id=${encodeURIComponent(A.C.clientId)}` +
    (withReturn ? `&returnTo=${encodeURIComponent(REDIRECT_URI)}` : '');
  log(`GET /logout → 302 ${url}`);
  res.redirect(url);
});

app.listen(port, () => log(`ЛР6 слухає ${REDIRECT_URI} (tenant=${A.C.name} ${A.C.domain})`));
