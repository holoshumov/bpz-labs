const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const crypto = require('crypto');
const { handshake, nextEvent, silent } = require('./helpers');
const { createMitm } = require('../src/mitm-core');
const { serveSession, filePayload } = require('../src/app');
const { CIPHER_SUITES } = require('../src/protocol');

test('повне рукостискання: обидві сторони отримують однакові ключі сеансу', async () => {
  const { c, s } = await handshake();
  assert.equal(c.status, 'fulfilled');
  assert.equal(s.status, 'fulfilled');
  const ck = c.value.keys; const sk = s.value.keys;
  for (const name of ['master', 'client_write_key', 'server_write_key', 'client_iv', 'server_iv']) {
    assert.deepEqual(ck[name], sk[name], `${name} однаковий`);
  }
  assert.equal(c.value.info.cipherSuite, CIPHER_SUITES[0]);
  // кожне рукостискання — нові random → нові ключі
  const again = await handshake();
  assert.notDeepEqual(again.c.value.keys.master, ck.master);
});

test('захищений канал: чат в обидва боки і файл із перевіркою SHA-256', async () => {
  const { c, s } = await handshake();
  const client = c.value; const server = s.value;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rgr-'));
  serveSession(server, { log: silent('server'), receivedDir: dir });
  client.start(); server.start();

  client.send({ kind: 'chat', text: 'привіт' });
  const ack = await nextEvent(client, 'data');
  assert.equal(ack.kind, 'ack');
  assert.match(ack.text, /привіт/);

  const file = path.join(__dirname, '..', 'samples', 'message.txt');
  const payload = filePayload(file);
  client.send(payload);
  const fack = await nextEvent(client, 'data');
  assert.equal(fack.kind, 'file_ack');
  assert.equal(fack.ok, true);
  assert.equal(fack.sha256, crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex'));
  assert.deepEqual(fs.readFileSync(path.join(dir, fack.saved_as)), fs.readFileSync(file));

  server.send({ kind: 'chat', from: 'server', text: 'відповідь' });
  assert.equal((await nextEvent(client, 'data')).text, 'відповідь');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('негатив 1: MITM підміняє публічний ключ → finished не сходиться, з\'єднання розірвано', async () => {
  const mitm = createMitm('keyswap', silent('mitm'));
  const { c, s } = await handshake({ filters: { c2s: mitm.c2s, s2c: mitm.s2c } });
  assert.equal(s.status, 'rejected');
  assert.equal(s.reason.code, 'bad_finished');
  assert.equal(c.status, 'rejected');
  assert.match(c.reason.message, /alert.*finished/);
});

test('негатив 1б (бонус X.509): MITM підміняє ключ, але сертифікат лишається → клієнт відхиляє на кроці 2', async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rgr-cert-'));
  try {
    execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-keyout', path.join(dir, 'k.pem'),
      '-out', path.join(dir, 'c.pem'), '-subj', '/CN=localhost'], { stdio: 'ignore' });
  } catch {
    t.skip('openssl недоступний');
    return;
  }
  const privateKey = fs.readFileSync(path.join(dir, 'k.pem'), 'utf8');
  const keys = { privateKey, publicKey: crypto.createPublicKey(privateKey).export({ type: 'spki', format: 'pem' }), certificate: fs.readFileSync(path.join(dir, 'c.pem'), 'utf8') };
  fs.rmSync(dir, { recursive: true, force: true });

  const ok = await handshake({ keys });
  assert.equal(ok.c.status, 'fulfilled', 'без MITM сертифікат приймається');

  const mitm = createMitm('keyswap-cert', silent('mitm'));
  const { c, s } = await handshake({ keys, filters: { c2s: mitm.c2s, s2c: mitm.s2c } });
  assert.equal(c.status, 'rejected');
  assert.equal(c.reason.code, 'certificate_key_mismatch');
  assert.equal(s.status, 'rejected');
});

test('негатив 2: змінений 1 байт шифротексту → AES-GCM відхиляє (unable to authenticate data)', async () => {
  const mitm = createMitm('tamper', silent('mitm'));
  const { c, s } = await handshake({ filters: { c2s: mitm.c2s, s2c: mitm.s2c } });
  const client = c.value.start(); const server = s.value.start();
  const serverFail = nextEvent(server, 'fail');
  const clientFail = nextEvent(client, 'fail');
  client.send({ kind: 'chat', text: 'секрет' });
  const e = await serverFail;
  assert.equal(e.code, 'bad_record_mac');
  assert.match(e.message, /unable to authenticate data/);
  assert.equal((await clientFail).code, 'alert');
});

test('негатив 3: повтор (replay) повідомлення → відхилено за номером послідовності', async () => {
  const mitm = createMitm('replay', silent('mitm'));
  const { c, s } = await handshake({ filters: { c2s: mitm.c2s, s2c: mitm.s2c } });
  const client = c.value.start(); const server = s.value.start();
  const received = [];
  server.on('data', (p) => received.push(p));
  const serverFail = nextEvent(server, 'fail');
  client.send({ kind: 'chat', text: 'переказати 100 грн' });
  const e = await serverFail;
  assert.equal(e.code, 'bad_seq');
  assert.match(e.message, /seq=1, очікувався seq=2/);
  assert.equal(received.length, 1, 'оригінал прийнято рівно один раз');
});

test('негатив 4: невірний finished → рукостискання не завершується', async () => {
  const { c, s } = await handshake({ client: { corruptFinished: true } });
  assert.equal(s.status, 'rejected');
  assert.equal(s.reason.code, 'bad_finished');
  assert.equal(c.status, 'rejected');
  assert.equal(c.reason.code, 'alert');
});

test('немає спільного набору шифрів (спроба downgrade) → alert', async () => {
  const { c, s } = await handshake({ client: { cipherSuites: ['NULL_WITH_NULL'] } });
  assert.equal(s.reason.code, 'handshake_failure');
  assert.equal(c.status, 'rejected');
});
