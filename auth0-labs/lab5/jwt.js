// ЛР5: перевірка підпису Auth0 JWT і шифрування в JWE (бібліотека jose).
const fs = require('fs');
const path = require('path');
const jose = require('jose');
const A = require('../common/auth0');

// --- Перевірка підпису ---
// Публічні ключі tenant'а: https://<domain>/.well-known/jwks.json (кешуються jose, вибір за kid)
const JWKS = jose.createRemoteJWKSet(new URL(`https://${A.C.domain}/.well-known/jwks.json`));
const ISSUER = `https://${A.C.domain}/`;

async function verifyAuth0(token) {
  const { payload, protectedHeader } = await jose.jwtVerify(token, JWKS, {
    issuer: ISSUER,          // iss
    audience: A.C.audience,  // aud (власний API або Management API на tenant викладача)
    algorithms: ['RS256'],   // забороняємо alg=none / HS256-підміну
  });                        // exp/nbf перевіряються автоматично
  return { payload, protectedHeader };
}

// --- JWE ---
// Ключова пара RSA-OAEP-256 сервера: генерується один раз і зберігається в lab5/keys (у .gitignore).
const KEY_DIR = path.join(__dirname, 'keys');
let keysPromise;
function keys() {
  keysPromise ??= (async () => {
    const pubFile = path.join(KEY_DIR, 'jwe-public.pem');
    const privFile = path.join(KEY_DIR, 'jwe-private.pem');
    if (!fs.existsSync(privFile)) {
      const { publicKey, privateKey } = await jose.generateKeyPair('RSA-OAEP-256', { modulusLength: 2048, extractable: true });
      fs.mkdirSync(KEY_DIR, { recursive: true });
      fs.writeFileSync(pubFile, await jose.exportSPKI(publicKey));
      fs.writeFileSync(privFile, await jose.exportPKCS8(privateKey), { mode: 0o600 });
    }
    return {
      publicKey: await jose.importSPKI(fs.readFileSync(pubFile, 'utf8'), 'RSA-OAEP-256'),
      privateKey: await jose.importPKCS8(fs.readFileSync(privFile, 'utf8'), 'RSA-OAEP-256'),
    };
  })();
  return keysPromise;
}

// Усередині JWE — дані з Auth0-токена (claims) і сам підписаний токен (для повторної перевірки підпису).
async function encrypt(auth0Token) {
  const { publicKey } = await keys();
  const { payload } = A.decode(auth0Token);
  return new jose.CompactEncrypt(
    new TextEncoder().encode(JSON.stringify({
      sub: payload.sub, iss: payload.iss, aud: payload.aud, exp: payload.exp, scope: payload.scope,
      auth0_token: auth0Token,
    })),
  )
    .setProtectedHeader({ alg: 'RSA-OAEP-256', enc: 'A256GCM', typ: 'JWE', cty: 'JSON' })
    .encrypt(publicKey);
}

async function decrypt(jwe) {
  const { privateKey } = await keys();
  const { plaintext, protectedHeader } = await jose.compactDecrypt(jwe, privateKey, {
    keyManagementAlgorithms: ['RSA-OAEP-256'],
    contentEncryptionAlgorithms: ['A256GCM'],
  });
  return { inner: JSON.parse(new TextDecoder().decode(plaintext)), protectedHeader };
}

// Вхід сервера: JWE (5 частин) → розшифрувати → перевірити підпис Auth0-токена; JWS (3 частини) → лише перевірка.
async function unwrapAndVerify(token) {
  const parts = token.split('.').length;
  let auth0Token = token;
  let wasJwe = false;
  if (parts === 5) {
    auth0Token = (await decrypt(token)).inner.auth0_token;
    wasJwe = true;
  }
  const { payload } = await verifyAuth0(auth0Token);
  return { auth0Token, payload, wasJwe };
}

module.exports = { verifyAuth0, encrypt, decrypt, unwrapAndVerify, keys, JWKS, ISSUER };
