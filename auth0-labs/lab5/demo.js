// ЛР5: демонстрація перевірки підпису і JWE. Сервер lab5 має бути запущений (npm run lab5).
const jose = require('jose');
const A = require('../common/auth0');
const log = A.evidence(__dirname, `demo-${A.C.name}`);
const BASE = `http://localhost:${A.E.PORT || 3000}`;
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');

async function get(title, token) {
  const r = await fetch(BASE + '/', { headers: { Authorization: `Bearer ${token}` } });
  const body = await r.json().catch(() => null);
  log(`${title} → HTTP ${r.status}`, body);
  return r.status;
}

(async () => {
  // 1. Вхід → сервер видає JWE
  const lr = await fetch(BASE + '/api/login', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ login: A.TEST.email, password: A.TEST.password }),
  });
  const { token: jwe } = await lr.json();
  const parts = jwe.split('.');
  log('POST /api/login → JWE від сервера', { token: jwe, parts: parts.length, header: JSON.parse(Buffer.from(parts[0], 'base64url')) });
  log('Спроба прочитати payload JWE без ключа (base64url-декодування 4-ї частини = шифротекст)', {
    ciphertext_as_text: Buffer.from(parts[3], 'base64url').toString('utf8').slice(0, 60),
    json_parse: (() => { try { JSON.parse(Buffer.from(parts[3], 'base64url')); return 'ok'; } catch (e) { return `помилка: ${e.message}`; } })(),
  });
  const otherKey = (await jose.generateKeyPair('RSA-OAEP-256')).privateKey;
  try { await jose.compactDecrypt(jwe, otherKey); } catch (e) { log('Розшифрування чужим приватним ключем', { error: e.code, message: e.message }); }

  // 2. Валідний JWE → 200
  await get('GET / з валідним JWE', jwe);

  // 3. Пошкоджений JWE (змінено байт шифротексту) → 401 (AES-GCM tag не сходиться)
  const bad = [...parts]; bad[3] = (bad[3][0] === 'A' ? 'B' : 'A') + bad[3].slice(1);
  await get('GET / з пошкодженим JWE', bad.join('.'));

  // 4. Справжній Auth0-токен (JWS) без шифрування → підпис валідний → 200
  const login = await A.passwordLogin(A.TEST.email, A.TEST.password);
  const jws = login.body.access_token;
  await get('GET / з оригінальним Auth0 JWS (RS256)', jws);

  // 5. Підміна payload (sub → чужий користувач), підпис старий → 401
  const [h, p, s] = jws.split('.');
  const forged = { ...JSON.parse(Buffer.from(p, 'base64url')), sub: 'auth0|attacker', scope: 'admin' };
  await get('GET / з підміненим payload (sub/scope), старий підпис', `${h}.${b64(forged)}.${s}`);

  // 6. Чужий токен: ті самі iss/aud/kid, але підписаний ключем зловмисника → 401
  const { privateKey } = await jose.generateKeyPair('RS256');
  const kid = JSON.parse(Buffer.from(h, 'base64url')).kid;
  const foreign = await new jose.SignJWT({ sub: 'auth0|attacker', scope: 'openid' })
    .setProtectedHeader({ alg: 'RS256', kid, typ: 'JWT' })
    .setIssuer(`https://${A.C.domain}/`).setAudience(A.C.audience).setIssuedAt().setExpirationTime('1h')
    .sign(privateKey);
  await get('GET / з чужим токеном (підписаний іншим RSA-ключем)', foreign);

  // 7. alg=none → 401
  await get('GET / з alg=none', `${b64({ alg: 'none', typ: 'JWT' })}.${b64(forged)}.`);

  // 8. Перевірка exp: справжній Auth0-токен (підпис валідний), але перевіряємо його «в момент після exp»
  const J = require('./jwt');
  const exp = A.decode(jws).payload.exp;
  try {
    await jose.jwtVerify(jws, J.JWKS, { issuer: J.ISSUER, audience: A.C.audience, algorithms: ['RS256'], currentDate: new Date((exp + 1) * 1000) });
  } catch (e) { log('jwtVerify справжнього токена на момент exp+1 с → відхилено', { code: e.code, message: e.message, claim: e.claim }); }
  // 9. Неправильна audience → відхилено
  try { await jose.jwtVerify(jws, J.JWKS, { issuer: J.ISSUER, audience: 'https://other-api', algorithms: ['RS256'] }); }
  catch (e) { log('jwtVerify з чужою audience → відхилено', { code: e.code, message: e.message, claim: e.claim }); }
})().catch((e) => { console.error(e); process.exit(1); });
