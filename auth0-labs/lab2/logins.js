// ЛР2 (макс. бал): 10 входів у різний час з різними наборами ролей.
// Використання: node lab2/logins.js [кількість=10] [інтервал_хв=5]
const A = require('../common/auth0');
const log = A.evidence(__dirname, `logins-${A.C.name}`);
const COUNT = Number(process.argv[2] || 10);
const INTERVAL_MIN = Number(process.argv[3] || 5);
const ROLE_SETS = [
  ['viewer'], ['editor'], ['admin'], ['viewer', 'editor'], ['editor', 'admin'],
  ['viewer', 'admin'], ['viewer', 'editor', 'admin'], [], ['admin'], ['viewer'],
];
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function setRoles(userId, wanted) {
  const all = await A.mgmt('GET', '/roles?per_page=100');
  if (all.status !== 200) return { ok: false, status: all.status };
  const id = (n) => all.body.find((r) => r.name === n)?.id;
  const uid = encodeURIComponent(userId);
  const cur = await A.mgmt('GET', `/users/${uid}/roles`);
  const curIds = (cur.body || []).map((r) => r.id);
  if (curIds.length) await A.mgmt('DELETE', `/users/${uid}/roles`, { roles: curIds });
  const ids = wanted.map(id).filter(Boolean);
  if (ids.length) await A.mgmt('POST', `/users/${uid}/roles`, { roles: ids });
  const after = await A.mgmt('GET', `/users/${uid}/roles`);
  return { ok: true, roles: (after.body || []).map((r) => r.name) };
}

(async () => {
  const user = await A.findUserByEmail(A.TEST.email);
  if (!user) throw new Error('Спершу запустіть lab2/run.js (створення користувача)');
  log(`Старт: ${COUNT} входів, інтервал ${INTERVAL_MIN} хв, user ${user.user_id}`);
  for (let i = 0; i < COUNT; i++) {
    const wanted = ROLE_SETS[i % ROLE_SETS.length];
    const r = await setRoles(user.user_id, wanted);
    const login = await A.passwordLogin(A.TEST.email, A.TEST.password);
    const p = login.status === 200 ? A.decode(login.body.access_token).payload : null;
    log(`Вхід #${i + 1}/${COUNT} → ${login.status} (${login.grant})`, {
      roles_requested: wanted,
      roles_now: r.ok ? r.roles : `недоступно (HTTP ${r.status})`,
      access_token: login.body?.access_token,
      iat: p && new Date(p.iat * 1000).toISOString(),
      exp: p && new Date(p.exp * 1000).toISOString(),
      error: login.body?.error_description,
    });
    if (i < COUNT - 1) await sleep(INTERVAL_MIN * 60_000);
  }
  log('Готово');
})().catch((e) => { console.error(e); process.exit(1); });
