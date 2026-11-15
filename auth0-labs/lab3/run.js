// ЛР3: password grant → refresh_token grant → зміна пароля (токен client_credentials) → перевірка.
const fs = require('fs');
const path = require('path');
const A = require('../common/auth0');
const log = A.evidence(__dirname, `run-${A.C.name}`);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const times = (t) => { const p = A.decode(t).payload; return { iat: p.iat, exp: p.exp, iat_human: new Date(p.iat * 1000).toISOString(), exp_human: new Date(p.exp * 1000).toISOString() }; };

(async () => {
  const email = A.TEST.email;
  const oldPass = A.TEST.password;
  const newPass = A.TEST.newPassword;

  // 1. User token (password grant)
  const login = await A.passwordLogin(email, oldPass);
  log(`POST /oauth/token grant_type=${login.grant} audience=${A.C.audience} → ${login.status}`, A.rr(login));
  if (login.status !== 200) process.exit(1);
  log('access_token payload', A.decode(login.body.access_token).payload);
  log('id_token payload', A.decode(login.body.id_token).payload);
  const t1 = times(login.body.access_token);

  // 2. Refresh
  await sleep(3000); // щоб iat/exp гарантовано відрізнялись
  const ref = await A.refresh(login.body.refresh_token);
  log(`POST /oauth/token grant_type=refresh_token → ${ref.status}`, A.rr(ref));
  if (ref.status === 200) {
    const t2 = times(ref.body.access_token);
    log('Порівняння iat/exp: старий vs новий access_token', { old: t1, new: t2, changed: t1.iat !== t2.iat && t1.exp !== t2.exp });
  }

  // 3. Зміна пароля з токеном client_credentials (ЛР2)
  const user = await A.findUserByEmail(email);
  const patch = await A.mgmt('PATCH', `/users/${encodeURIComponent(user.user_id)}`, { password: newPass, connection: A.CONNECTION });
  log(`PATCH /api/v2/users/${user.user_id} {password} → ${patch.status}`, A.rr(patch));
  if (patch.status !== 200) {
    log('Зміна пароля недоступна на цьому tenant (немає scope update:users) — виконайте з TENANT=own');
    return;
  }
  const withOld = await A.passwordLogin(email, oldPass);
  log(`Вхід зі СТАРИМ паролем → ${withOld.status}`, A.rr(withOld));
  const withNew = await A.passwordLogin(email, newPass);
  log(`Вхід з НОВИМ паролем → ${withNew.status}`, A.rr(withNew));

  // Міняємо паролі місцями в .env, щоб скрипт можна було запускати повторно.
  const envPath = path.join(__dirname, '..', '.env');
  const env = fs.readFileSync(envPath, 'utf8')
    .replace(/^TEST_USER_PASSWORD=.*$/m, `TEST_USER_PASSWORD=${newPass}`)
    .replace(/^TEST_USER_NEW_PASSWORD=.*$/m, `TEST_USER_NEW_PASSWORD=${oldPass}`);
  fs.writeFileSync(envPath, env);
  log('.env: TEST_USER_PASSWORD і TEST_USER_NEW_PASSWORD поміняно місцями');
})().catch((e) => { console.error(e); process.exit(1); });
