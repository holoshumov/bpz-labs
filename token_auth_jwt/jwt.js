// Мінімальна реалізація JWT (HS256) на вбудованому модулі crypto.
// Формат: base64url(header).base64url(payload).base64url(HMAC-SHA256(header.payload, secret))
const crypto = require('crypto');

const b64url = (input) => Buffer.from(input).toString('base64url');
const fromB64url = (str) => Buffer.from(str, 'base64url').toString('utf8');

function hmac(data, secret) {
    return crypto.createHmac('sha256', secret).update(data).digest('base64url');
}

function sign(payload, secret, expiresInSec = 3600) {
    const header = { alg: 'HS256', typ: 'JWT' };
    const now = Math.floor(Date.now() / 1000);
    const body = { ...payload, iat: now, exp: now + expiresInSec };

    const unsigned = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(body))}`;
    return `${unsigned}.${hmac(unsigned, secret)}`;
}

// Повертає payload, якщо токен валідний, інакше кидає помилку
function verify(token, secret) {
    const parts = String(token).split('.');
    if (parts.length !== 3) throw new Error('Malformed token');

    const [h, p, s] = parts;
    const header = JSON.parse(fromB64url(h));
    if (header.alg !== 'HS256') throw new Error('Unsupported alg'); // захист від alg=none

    const expected = Buffer.from(hmac(`${h}.${p}`, secret));
    const actual = Buffer.from(s);
    if (expected.length !== actual.length || !crypto.timingSafeEqual(expected, actual)) {
        throw new Error('Invalid signature');
    }

    const payload = JSON.parse(fromB64url(p));
    if (payload.exp && Math.floor(Date.now() / 1000) >= payload.exp) {
        throw new Error('Token expired');
    }
    return payload;
}

function decode(token) {
    const [h, p] = String(token).split('.');
    return { header: JSON.parse(fromB64url(h)), payload: JSON.parse(fromB64url(p)) };
}

module.exports = { sign, verify, decode };
