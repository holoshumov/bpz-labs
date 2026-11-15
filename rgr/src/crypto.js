// Криптографічні примітиви — лише вбудований модуль node:crypto.
const crypto = require('crypto');

const random = (n) => crypto.randomBytes(n);

// --- RSA (крок 2 і 4) ---
function generateRsaKeyPair() {
  return crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
}

const OAEP = { padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' };
const rsaEncrypt = (publicKeyPem, data) => crypto.publicEncrypt({ key: publicKeyPem, ...OAEP }, data);
const rsaDecrypt = (privateKeyPem, data) => crypto.privateDecrypt({ key: privateKeyPem, ...OAEP }, data);

const toPublicKey = (key) => (key instanceof crypto.KeyObject && key.type === 'public' ? key : crypto.createPublicKey(key));
const spkiDer = (key) => toPublicKey(key).export({ type: 'spki', format: 'der' });
const sameKey = (a, b) => spkiDer(a).equals(spkiDer(b));
// Відбиток публічного ключа: SHA-256 від SPKI (DER)
function keyFingerprint(key) {
  const h = crypto.createHash('sha256').update(spkiDer(key)).digest('hex').toUpperCase();
  return h.match(/../g).slice(0, 8).join(':') + '…';
}

// --- HKDF (крок 5) ---
const hkdf = (ikm, salt, info, length) => Buffer.from(crypto.hkdfSync('sha256', ikm, salt, Buffer.from(info, 'utf8'), length));

// master = HKDF-SHA256(premaster, salt = client_random ‖ server_random, info = "bpz master")
// окремі ключі для кожного напрямку — HKDF(master, той самий salt, різні info)
function deriveKeys(premaster, clientRandom, serverRandom) {
  const salt = Buffer.concat([clientRandom, serverRandom]);
  const master = hkdf(premaster, salt, 'bpz master', 48);
  const expand = (info, len) => hkdf(master, salt, info, len);
  return {
    master,
    client_write_key: expand('bpz client write key', 32), // AES-256
    server_write_key: expand('bpz server write key', 32),
    client_iv: expand('bpz client iv', 12),               // 96-бітний IV для GCM
    server_iv: expand('bpz server iv', 12),
  };
}

// --- AES-256-GCM (кроки 6–7) ---
// nonce = IV ⊕ seq (seq — 64 біти в останніх 8 байтах), як у TLS 1.3: унікальний для кожного повідомлення.
function nonceFor(iv, seq) {
  const nonce = Buffer.from(iv);
  const s = Buffer.alloc(8);
  s.writeBigUInt64BE(BigInt(seq));
  for (let i = 0; i < 8; i++) nonce[4 + i] ^= s[i];
  return nonce;
}

function aesGcmEncrypt(key, nonce, plaintext, aad) {
  const c = crypto.createCipheriv('aes-256-gcm', key, nonce);
  c.setAAD(aad);
  const ct = Buffer.concat([c.update(plaintext), c.final()]);
  return { ct, tag: c.getAuthTag() };
}

function aesGcmDecrypt(key, nonce, ct, tag, aad) {
  const d = crypto.createDecipheriv('aes-256-gcm', key, nonce);
  d.setAAD(aad);
  d.setAuthTag(tag);
  return Buffer.concat([d.update(ct), d.final()]); // кидає "Unsupported state or unable to authenticate data"
}

// --- Transcript hash і finished (крок 6) ---
// SHA-256 від усіх повідомлень рукостискання в тому вигляді, як їх було відправлено/отримано.
const transcriptHash = (raws) => crypto.createHash('sha256').update(raws.join('\n'), 'utf8').digest();
// verify_data = HMAC-SHA256(master, label ‖ transcript_hash)
const verifyData = (master, label, thash) => crypto.createHmac('sha256', master).update(label).update(thash).digest();

function safeEqualHex(hex, expected) {
  const got = Buffer.from(typeof hex === 'string' ? hex : '', 'hex');
  return got.length === expected.length && crypto.timingSafeEqual(got, expected);
}

const sha256 = (data) => crypto.createHash('sha256').update(data).digest('hex');

module.exports = {
  random, generateRsaKeyPair, rsaEncrypt, rsaDecrypt, sameKey, keyFingerprint,
  hkdf, deriveKeys, nonceFor, aesGcmEncrypt, aesGcmDecrypt, transcriptHash, verifyData, safeEqualHex, sha256,
};
