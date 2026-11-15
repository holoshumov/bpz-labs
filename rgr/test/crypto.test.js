const test = require('node:test');
const assert = require('node:assert/strict');
const K = require('../src/crypto');
const { SecureChannel } = require('../src/channel');
const { FrameDecoder, encodeFrame } = require('../src/protocol');
const { SERVER_KEYS } = require('./helpers');

test('RSA-OAEP(SHA-256): шифрування публічним і розшифрування приватним ключем', () => {
  const pm = K.random(48);
  const enc = K.rsaEncrypt(SERVER_KEYS.publicKey, pm);
  assert.equal(enc.length, 256);
  assert.deepEqual(K.rsaDecrypt(SERVER_KEYS.privateKey, enc), pm);
  // OAEP рандомізований: той самий premaster дає різний шифротекст
  assert.notDeepEqual(K.rsaEncrypt(SERVER_KEYS.publicKey, pm), enc);
});

test('HKDF: детермінований, залежить від усіх трьох входів, ключі напрямків різні', () => {
  const pm = K.random(48); const cr = K.random(32); const sr = K.random(32);
  const a = K.deriveKeys(pm, cr, sr);
  const b = K.deriveKeys(pm, cr, sr);
  assert.deepEqual(a, b);
  assert.notDeepEqual(K.deriveKeys(pm, K.random(32), sr).master, a.master);
  assert.notDeepEqual(K.deriveKeys(pm, cr, K.random(32)).master, a.master);
  assert.notDeepEqual(K.deriveKeys(K.random(48), cr, sr).master, a.master);
  assert.notDeepEqual(a.client_write_key, a.server_write_key);
  assert.equal(a.client_write_key.length, 32);
  assert.equal(a.client_iv.length, 12);
});

test('AES-256-GCM: шифр/дешифр, nonce унікальний для кожного seq', () => {
  const key = K.random(32); const iv = K.random(12);
  const n0 = K.nonceFor(iv, 0); const n1 = K.nonceFor(iv, 1);
  assert.deepEqual(n0, iv);
  assert.notDeepEqual(n0, n1);
  const { ct, tag } = K.aesGcmEncrypt(key, n1, Buffer.from('привіт'), Buffer.from('data|1'));
  assert.equal(K.aesGcmDecrypt(key, n1, ct, tag, Buffer.from('data|1')).toString(), 'привіт');
  assert.throws(() => K.aesGcmDecrypt(key, n1, ct, tag, Buffer.from('data|2')), /unable to authenticate/);
});

test('SecureChannel: дві сторони з дзеркальними ключами обмінюються повідомленнями', () => {
  const k = K.deriveKeys(K.random(48), K.random(32), K.random(32));
  const c = new SecureChannel({ sendKey: k.client_write_key, sendIv: k.client_iv, recvKey: k.server_write_key, recvIv: k.server_iv });
  const s = new SecureChannel({ sendKey: k.server_write_key, sendIv: k.server_iv, recvKey: k.client_write_key, recvIv: k.client_iv });
  for (let i = 0; i < 3; i++) assert.deepEqual(s.open(c.seal('data', { i })), { i });
  assert.deepEqual(c.open(s.seal('data', { ok: true })), { ok: true });
  // підміна seq у повідомленні: seq входить у nonce і AAD → GCM відхиляє
  const m = c.seal('data', { x: 1 });
  assert.throws(() => s.open({ ...m, seq: m.seq + 1 }), /seq=4, очікувався seq=3/);
  const m2 = c.seal('data', { x: 2 });
  assert.throws(() => s.open({ ...m2, seq: 3 }), /AES-GCM відхилив/);
});

test('кадрування: повідомлення, розрізане на довільні шматки TCP, збирається', () => {
  const frames = Buffer.concat([encodeFrame('{"type":"data","a":1}'), encodeFrame('{"type":"alert"}')]);
  const dec = new FrameDecoder();
  const got = [];
  for (let i = 0; i < frames.length; i += 3) got.push(...dec.push(frames.subarray(i, i + 3)));
  assert.deepEqual(got, ['{"type":"data","a":1}', '{"type":"alert"}']);
});
