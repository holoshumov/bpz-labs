// Налаштування власного tenant'а через Management API (замість ручних кроків у Dashboard).
// Ідемпотентний: можна запускати повторно. Потрібні в .env: AUTH0_DOMAIN, AUTH0_ADMIN_CLIENT_ID/SECRET.
// Результат: AUTH0_CLIENT_ID / AUTH0_CLIENT_SECRET застосунку «BPZ Lab App» записуються в .env.
const fs = require('fs');
const path = require('path');
const ENV = path.join(__dirname, '..', '.env');
require('dotenv').config({ path: ENV });
const E = process.env;
const D = E.AUTH0_DOMAIN;
const API_ID = E.AUTH0_AUDIENCE || 'https://bpz-lab-api';
const APP_NAME = 'BPZ Lab App';
const CONNECTION = 'Username-Password-Authentication';
const MGMT_SCOPES = [
  'read:users', 'create:users', 'update:users',
  'read:roles', 'create:roles', 'update:roles', 'delete:roles',
  'create:role_members', 'read:role_members', 'delete:role_members',
  'read:users_app_metadata',
];
const log = (m, d) => console.log(`[${new Date().toISOString()}] ${m}`, d === undefined ? '' : JSON.stringify(d));

let TOKEN;
async function api(method, p, body) {
  const r = await fetch(`https://${D}/api/v2${p}`, {
    method,
    headers: { authorization: `Bearer ${TOKEN}`, 'content-type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
  });
  const t = await r.text();
  const j = t ? JSON.parse(t) : null;
  if (r.status >= 400) throw new Error(`${method} ${p} → ${r.status} ${t}`);
  return j;
}

function setEnv(key, value) {
  let s = fs.readFileSync(ENV, 'utf8');
  s = new RegExp(`^${key}=.*$`, 'm').test(s) ? s.replace(new RegExp(`^${key}=.*$`, 'm'), `${key}=${value}`) : `${s.trimEnd()}\n${key}=${value}\n`;
  fs.writeFileSync(ENV, s, { mode: 0o600 });
}

(async () => {
  const tr = await fetch(`https://${D}/oauth/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'client_credentials', client_id: E.AUTH0_ADMIN_CLIENT_ID, client_secret: E.AUTH0_ADMIN_CLIENT_SECRET, audience: `https://${D}/api/v2/` }),
  }).then((r) => r.json());
  if (!tr.access_token) throw new Error(JSON.stringify(tr));
  TOKEN = tr.access_token;
  log('Адмін-токен Management API отримано');

  // 1. Власний API: RS256, Allow Offline Access
  const servers = await api('GET', '/resource-servers?per_page=100');
  let rs = servers.find((s) => s.identifier === API_ID);
  const rsBody = { name: 'BPZ Lab API', signing_alg: 'RS256', allow_offline_access: true, token_lifetime: Number(E.API_TOKEN_TTL || 120) /* короткий TTL для демо автооновлення (ЛР4) */, skip_consent_for_verifiable_first_party_clients: true };
  rs = rs ? await api('PATCH', `/resource-servers/${rs.id}`, rsBody) : await api('POST', '/resource-servers', { identifier: API_ID, ...rsBody });
  log('API', { identifier: rs.identifier, signing_alg: rs.signing_alg, allow_offline_access: rs.allow_offline_access });

  // 2. Застосунок Regular Web: grant types, callback/logout URLs
  const clients = await api('GET', '/clients?per_page=100&fields=client_id,name');
  let app = clients.find((c) => c.name === APP_NAME);
  const appBody = {
    app_type: 'regular_web',
    token_endpoint_auth_method: 'client_secret_post',
    grant_types: ['authorization_code', 'refresh_token', 'client_credentials', 'password'],
    callbacks: ['http://localhost:3000', 'http://localhost:3000/callback'],
    allowed_logout_urls: ['http://localhost:3000'],
    web_origins: ['http://localhost:3000'],
    oidc_conformant: true,
    jwt_configuration: { alg: 'RS256' },
    refresh_token: { rotation_type: 'non-rotating', expiration_type: 'non-expiring' },
  };
  app = app ? await api('PATCH', `/clients/${app.client_id}`, appBody) : await api('POST', '/clients', { name: APP_NAME, ...appBody });
  log('Застосунок', { name: app.name, client_id: app.client_id, grant_types: app.grant_types, callbacks: app.callbacks });

  // 3. Доступ застосунку до Management API (client_credentials) зі scopes
  const mgmtAud = `https://${D}/api/v2/`;
  const grants = await api('GET', `/client-grants?client_id=${app.client_id}`);
  let g = grants.find((x) => x.audience === mgmtAud);
  g = g ? await api('PATCH', `/client-grants/${g.id}`, { scope: MGMT_SCOPES }) : await api('POST', '/client-grants', { client_id: app.client_id, audience: mgmtAud, scope: MGMT_SCOPES });
  log('Management API scopes', g.scope);
  // і до власного API (client_credentials теж дозволено)
  if (!grants.find((x) => x.audience === API_ID)) await api('POST', '/client-grants', { client_id: app.client_id, audience: API_ID, scope: [] });

  // 4. Connection Username-Password-Authentication увімкнено для застосунку
  const conns = await api('GET', `/connections?name=${CONNECTION}`);
  const conn = conns[0];
  if (Array.isArray(conn.enabled_clients)) {
    if (!conn.enabled_clients.includes(app.client_id)) {
      await api('PATCH', `/connections/${conn.id}`, { enabled_clients: [...conn.enabled_clients, app.client_id] });
    }
  } else {
    await api('PATCH', `/connections/${conn.id}/clients`, [{ client_id: app.client_id, status: true }]);
  }
  log('Connection увімкнено для застосунку', CONNECTION);

  // 5. Tenant Settings → Default Directory (для password grant)
  const ts = await api('PATCH', '/tenants/settings', { default_directory: CONNECTION });
  log('Default Directory', ts.default_directory);

  // 6. .env
  const full = await api('GET', `/clients/${app.client_id}?fields=client_id,client_secret`);
  setEnv('AUTH0_CLIENT_ID', full.client_id);
  setEnv('AUTH0_CLIENT_SECRET', full.client_secret);
  setEnv('AUTH0_AUDIENCE', API_ID);
  setEnv('AUTH0_MGMT_AUDIENCE', mgmtAud);
  log('.env оновлено: AUTH0_CLIENT_ID, AUTH0_CLIENT_SECRET, AUTH0_AUDIENCE, AUTH0_MGMT_AUDIENCE');
})().catch((e) => { console.error(e.message); process.exit(1); });
