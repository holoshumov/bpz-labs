// Спільний клієнт Auth0 для ЛР2–ЛР6.
// Вибір tenant'а: TENANT=own|kpi (за замовчуванням own, якщо AUTH0_DOMAIN заповнено, інакше kpi).
const path = require('path');
const fs = require('fs');
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });

const E = process.env;

function cfg() {
  const want = E.TENANT || (E.AUTH0_DOMAIN ? 'own' : 'kpi');
  if (want === 'own') {
    if (!E.AUTH0_DOMAIN) throw new Error('TENANT=own, але AUTH0_DOMAIN у .env порожній');
    return {
      name: 'own',
      domain: E.AUTH0_DOMAIN,
      clientId: E.AUTH0_CLIENT_ID,
      clientSecret: E.AUTH0_CLIENT_SECRET,
      audience: E.AUTH0_AUDIENCE, // власний API (RS256, offline access)
      mgmtAudience: E.AUTH0_MGMT_AUDIENCE || `https://${E.AUTH0_DOMAIN}/api/v2/`,
    };
  }
  return {
    name: 'kpi',
    domain: E.KPI_DOMAIN,
    clientId: E.KPI_CLIENT_ID,
    clientSecret: E.KPI_CLIENT_SECRET,
    audience: E.KPI_AUDIENCE, // на tenant викладача власного API немає → Management API
    mgmtAudience: E.KPI_AUDIENCE,
  };
}

const C = cfg();
// Тестовий користувач. На tenant викладача пароль змінити не можна (немає update:users),
// тому там він окремий: KPI_TEST_USER_PASSWORD.
const TEST = {
  email: E.TEST_USER_EMAIL,
  password: C.name === 'kpi' ? (E.KPI_TEST_USER_PASSWORD || E.TEST_USER_PASSWORD) : E.TEST_USER_PASSWORD,
  newPassword: E.TEST_USER_NEW_PASSWORD,
};
const CONNECTION = 'Username-Password-Authentication';

// ---------- утиліти ----------
const ts = () => new Date().toISOString();
const short = (t) => (typeof t === 'string' && t.length > 24 ? `${t.slice(0, 10)}...${t.slice(-6)}` : t);
function decode(jwt) {
  const [h, p] = jwt.split('.');
  return {
    header: JSON.parse(Buffer.from(h, 'base64url')),
    payload: JSON.parse(Buffer.from(p, 'base64url')),
  };
}
const SECRET_KEYS = /token|secret|password|^code$|^authorization$|code_verifier/i;
function redact(obj) {
  if (Array.isArray(obj)) return obj.map(redact);
  if (obj && typeof obj === 'object') {
    return Object.fromEntries(
      Object.entries(obj).map(([k, v]) => [k,
        typeof v === 'string' && /password/i.test(k) ? '********'
          : SECRET_KEYS.test(k) && typeof v === 'string' ? short(v) : redact(v)]),
    );
  }
  return obj;
}

function maskCreds(obj) {
  if (Array.isArray(obj)) return obj.map(maskCreds);
  if (obj && typeof obj === 'object') {
    return Object.fromEntries(Object.entries(obj).map(([k, v]) => [k,
      typeof v === 'string' && /password|client_secret/i.test(k) ? '********' : maskCreds(v)]));
  }
  return obj;
}

// Журнал доказів: evidence/<name>.log (обрізані секрети, йде в git)
// і evidence/raw/<name>.log (повні токени для скріншотів, у .gitignore).
function evidence(labDir, name) {
  const dir = path.join(labDir, 'evidence');
  fs.mkdirSync(path.join(dir, 'raw'), { recursive: true });
  const safe = path.join(dir, `${name}.log`);
  const raw = path.join(dir, 'raw', `${name}.log`);
  const write = (file, text) => fs.appendFileSync(file, text + '\n');
  return function log(title, data) {
    const head = `[${ts()}] [tenant=${C.name} ${C.domain}] ${title}`;
    // у raw токени повні (для jwt.io / скріншотів), але client_secret і паролі приховано й там
    const full = data === undefined ? head : `${head}\n${JSON.stringify(maskCreds(data), null, 2)}`;
    const cut = data === undefined ? head : `${head}\n${JSON.stringify(redact(data), null, 2)}`;
    write(raw, full);
    write(safe, cut);
    console.log(cut);
  };
}

// ---------- HTTP ----------
async function http(method, url, { body, form, token } = {}) {
  const headers = {};
  let payload;
  if (form) {
    headers['content-type'] = 'application/x-www-form-urlencoded';
    payload = new URLSearchParams(form).toString();
  } else if (body !== undefined) {
    headers['content-type'] = 'application/json';
    payload = JSON.stringify(body);
  }
  if (token) headers.authorization = `Bearer ${token}`;
  const res = await fetch(url, { method, headers, body: payload });
  const text = await res.text();
  let json;
  try { json = text ? JSON.parse(text) : null; } catch { json = text; }
  return {
    status: res.status,
    body: json,
    // запит для журналу доказів (секрети обрізає redact() під час запису в evidence/*.log)
    request: { method, url, headers: { ...headers }, body: form || body },
  };
}

// Пара «запит + відповідь» для журналу
const rr = (r) => ({ request: r.request, response: { status: r.status, body: r.body } });

// ---------- OAuth2 ----------
function tokenEndpoint(form) {
  return http('POST', `https://${C.domain}/oauth/token`, {
    form: { client_id: C.clientId, client_secret: C.clientSecret, ...form },
  });
}

let mgmtCache = null; // { token, exp }
async function clientCredentials({ force = false } = {}) {
  const now = Math.floor(Date.now() / 1000);
  if (!force && mgmtCache && mgmtCache.exp - 60 > now) return { cached: true, ...mgmtCache };
  const r = await tokenEndpoint({ grant_type: 'client_credentials', audience: C.mgmtAudience });
  if (r.status !== 200) throw Object.assign(new Error('client_credentials failed'), { response: r });
  mgmtCache = { token: r.body.access_token, exp: now + r.body.expires_in, response: r };
  return { cached: false, ...mgmtCache };
}

// Password grant. Якщо в tenant'і не задано Default Directory (як у tenant викладача),
// Auth0 відповідає "Authorization server not configured with default connection" —
// тоді використовуємо розширення Auth0 password-realm з realm=Username-Password-Authentication.
async function passwordLogin(username, password, { audience = C.audience, scope = 'openid profile email offline_access' } = {}) {
  const base = { username, password, audience, scope };
  let r = await tokenEndpoint({ grant_type: 'password', ...base });
  r.grant = 'password';
  if (r.status !== 200 && /default connection/i.test(r.body?.error_description || '')) {
    r = await tokenEndpoint({
      grant_type: 'http://auth0.com/oauth/grant-type/password-realm',
      realm: CONNECTION,
      ...base,
    });
    r.grant = 'password-realm';
  }
  return r;
}

const refresh = (refresh_token) => tokenEndpoint({ grant_type: 'refresh_token', refresh_token });

const authCode = (code, redirect_uri, code_verifier) =>
  tokenEndpoint({ grant_type: 'authorization_code', code, redirect_uri, ...(code_verifier ? { code_verifier } : {}) });

async function mgmt(method, apiPath, body) {
  const { token } = await clientCredentials();
  return http(method, `https://${C.domain}/api/v2${apiPath}`, { body, token });
}

const userinfo = (accessToken) => http('GET', `https://${C.domain}/userinfo`, { token: accessToken });

async function findUserByEmail(email) {
  const r = await mgmt('GET', `/users-by-email?email=${encodeURIComponent(email)}`);
  return r.status === 200 && Array.isArray(r.body) ? r.body[0] : null;
}

module.exports = {
  C, CONNECTION, E, TEST, rr, ts, short, decode, redact, evidence,
  http, tokenEndpoint, clientCredentials, passwordLogin, refresh, authCode, mgmt, userinfo, findUserByEmail,
};
