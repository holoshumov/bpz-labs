// ЛР2: client_credentials → створення користувача → ролі (viewer/editor/admin) → призначення.
const A = require('../common/auth0');
const log = A.evidence(__dirname, `run-${A.C.name}`);
const ROLES = [
  { name: 'viewer', description: 'Read-only access (BPZ lab2)' },
  { name: 'editor', description: 'Can edit content (BPZ lab2)' },
  { name: 'admin', description: 'Full access (BPZ lab2)' },
];

async function ensureRoles() {
  const list = await A.mgmt('GET', '/roles?per_page=100');
  log(`GET /api/v2/roles → ${list.status}`, list.body);
  if (list.status !== 200) return null;
  const out = {};
  for (const r of ROLES) {
    let role = list.body.find((x) => x.name === r.name);
    if (!role) {
      const c = await A.mgmt('POST', '/roles', r);
      log(`POST /api/v2/roles (${r.name}) → ${c.status}`, c.body);
      role = c.body;
    }
    out[r.name] = role.id;
  }
  return out;
}

(async () => {
  // 1. Токен client_credentials для Management API
  const cc = await A.clientCredentials({ force: true });
  log('POST /oauth/token grant_type=client_credentials → 200', cc.response.body);
  const { header, payload } = A.decode(cc.token);
  log('Розкодований access_token (header + payload)', {
    header, payload,
    exp_human: new Date(payload.exp * 1000).toISOString(),
    iat_human: new Date(payload.iat * 1000).toISOString(),
  });

  // 2. Створення користувача: демонстраційний (новий email → 201) і основний тестовий
  const demo = { email: `lab2-demo-${Date.now()}@example.com`, password: A.E.TEST_USER_PASSWORD, connection: A.CONNECTION };
  const d = await A.mgmt('POST', '/users', demo);
  log(`POST /api/v2/users (демо-користувач) → ${d.status}`, { request: demo, response: d.body });
  const email = A.E.TEST_USER_EMAIL;
  const body = { email, password: A.E.TEST_USER_PASSWORD, connection: A.CONNECTION };
  const created = await A.mgmt('POST', '/users', body);
  log(`POST /api/v2/users → ${created.status}`, { request: { ...body }, response: created.body });
  let user = created.status === 201 ? created.body : await A.findUserByEmail(email);
  if (created.status === 409) log('Користувач уже існує, беремо наявного', { user_id: user?.user_id });
  if (!user) { log('Користувача не знайдено — зупинка'); process.exit(1); }

  // 3. Ролі (додаткове завдання)
  const roles = await ensureRoles();
  if (!roles) {
    log('Ролі недоступні на цьому tenant (немає scope read:roles/create:roles) — виконайте з TENANT=own');
    return;
  }
  const assign = await A.mgmt('POST', `/users/${encodeURIComponent(user.user_id)}/roles`, { roles: [roles.viewer] });
  log(`POST /api/v2/users/{id}/roles [viewer] → ${assign.status}`, assign.body);
  const cur = await A.mgmt('GET', `/users/${encodeURIComponent(user.user_id)}/roles`);
  log(`GET /api/v2/users/{id}/roles → ${cur.status}`, cur.body);
})().catch((e) => { console.error(e.response || e); process.exit(1); });
