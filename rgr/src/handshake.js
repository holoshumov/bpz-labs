// Стан-машина рукостискання для обох ролей (клієнт ініціює, сервер відповідає) і сеанс після нього.
// Роль — параметр «ноди», а не окремий застосунок: у розширеному варіанті кожна нода зможе бути і тим, і тим.
const crypto = require('crypto');
const { EventEmitter } = require('events');
const { VERSION, CIPHER_SUITES, ProtocolError } = require('./protocol');
const K = require('./crypto');
const { SecureChannel } = require('./channel');
const { createLogger } = require('./log');

// Черга вхідних повідомлень: рукостискання чекає конкретний тип (next), після нього — обробник сеансу.
class MessageQueue {
  constructor(transport) {
    this.items = [];
    this.waiters = [];
    this.handler = null;
    this.closedError = null;
    transport.on('message', (msg, raw) => this._push({ msg, raw }));
    transport.on('protocol_error', (e) => this._fail(e));
    transport.on('close', () => this._fail(new ProtocolError('closed', "з'єднання закрито іншою стороною")));
  }

  _push(item) {
    if (this.handler) return this.handler(item.msg, item.raw);
    const w = this.waiters.shift();
    if (w) w.take(item); else this.items.push(item);
  }

  _fail(e) {
    if (this.closedError) return;
    this.closedError = e;
    for (const w of this.waiters.splice(0)) w.reject(e);
  }

  next(expectedType) {
    return new Promise((resolve, reject) => {
      const take = (item) => {
        if (item.msg.type === 'alert') return reject(new ProtocolError('alert', `отримано alert: ${item.msg.reason}`));
        if (item.msg.type !== expectedType) return reject(new ProtocolError('unexpected_message', `очікувалось ${expectedType}, отримано ${item.msg.type}`));
        return resolve(item);
      };
      if (this.items.length) take(this.items.shift());
      else if (this.closedError) reject(this.closedError);
      else this.waiters.push({ take, reject });
    });
  }

  setHandler(handler) {
    this.handler = handler;
    while (this.items.length) { const i = this.items.shift(); handler(i.msg, i.raw); }
  }
}

// Сеанс після рукостискання: дані застосунку йдуть лише через SecureChannel.
class Session extends EventEmitter {
  constructor({ role, transport, queue, channel, keys, log, info }) {
    super();
    Object.assign(this, { role, transport, queue, channel, keys, log, info });
    this.failed = false;
  }

  start() {
    this.queue.setHandler((msg) => this._onMessage(msg));
    if (this.transport.closed) this.emit('close');
    else this.transport.on('close', () => this.emit('close'));
    return this;
  }

  _onMessage(msg) {
    if (this.failed) return;
    if (msg.type === 'alert') {
      this.failed = true;
      this.log.err(`отримано alert: ${msg.reason}`);
      this.transport.close();
      this.emit('fail', new ProtocolError('alert', msg.reason));
      return;
    }
    if (msg.type !== 'data') return this.abort(new ProtocolError('unexpected_message', `після рукостискання неочікуване ${msg.type}`));
    let payload;
    try { payload = this.channel.open(msg); } catch (e) { return this.abort(e); }
    this.log.info(`← data seq=${msg.seq} (шифротекст ${Buffer.from(msg.ct, 'base64').length} Б, tag ${msg.tag.slice(0, 8)}…) розшифровано`);
    this.emit('data', payload, msg);
  }

  abort(e) {
    if (this.failed) return;
    this.failed = true;
    this.log.err(e.message);
    this.transport.send({ type: 'alert', reason: e.message });
    this.transport.close();
    this.emit('fail', e);
  }

  send(payload) {
    const msg = this.channel.seal('data', payload);
    this.transport.send(msg);
    this.log.info(`→ data seq=${msg.seq} (AES-256-GCM: шифротекст ${Buffer.from(msg.ct, 'base64').length} Б, tag ${msg.tag.slice(0, 8)}…)`);
    return msg;
  }

  close() { this.transport.close(); }
}

// Будь-яка помилка рукостискання → alert іншій стороні та розрив з'єднання.
async function guarded(transport, log, fn) {
  try {
    return await fn();
  } catch (e) {
    log.err(`рукостискання НЕ завершено: ${e.message}`);
    if (e.code !== 'alert' && e.code !== 'closed') transport.send({ type: 'alert', reason: e.message });
    transport.close();
    throw e;
  }
}

const describeKeys = (keys, frag) => Object.fromEntries(Object.entries(keys).map(([k, v]) => [k, frag(v)]));

function readRandom(hex, name) {
  const b = Buffer.from(typeof hex === 'string' ? hex : '', 'hex');
  if (b.length !== 32) throw new ProtocolError('bad_random', `${name} має бути 32 байти`);
  return b;
}

// ===== Клієнт =====
async function clientHandshake(transport, opts = {}) {
  const log = opts.log || createLogger('client', { silent: true });
  const queue = new MessageQueue(transport);
  const transcript = []; // сирі JSON-повідомлення рукостискання

  return guarded(transport, log, async () => {
    // Крок 1. client_hello з випадковим client_random
    const clientRandom = K.random(32);
    const hello = { type: 'client_hello', version: VERSION, client_random: clientRandom.toString('hex'), cipher_suites: opts.cipherSuites || CIPHER_SUITES };
    transcript.push(transport.send(hello));
    log.step(1, '→ client_hello', { version: VERSION, client_random: log.frag(clientRandom), cipher_suites: hello.cipher_suites.join(', ') });

    // Крок 2. server_hello: server_random, шифр, публічний ключ (і, як бонус, X.509-сертифікат)
    const { msg: sh, raw: shRaw } = await queue.next('server_hello');
    transcript.push(shRaw);
    const serverRandom = readRandom(sh.server_random, 'server_random');
    if (!hello.cipher_suites.includes(sh.cipher_suite)) throw new ProtocolError('bad_cipher', `сервер обрав шифр, якого клієнт не пропонував: ${sh.cipher_suite}`);
    let serverKey;
    try { serverKey = crypto.createPublicKey(sh.public_key); } catch { throw new ProtocolError('bad_key', 'public_key сервера не є коректним PEM'); }
    if (serverKey.asymmetricKeyType !== 'rsa' || serverKey.asymmetricKeyDetails.modulusLength < 2048) throw new ProtocolError('bad_key', 'потрібен RSA-ключ ≥ 2048 біт');
    log.step(2, '← server_hello', {
      server_random: log.frag(serverRandom),
      cipher_suite: sh.cipher_suite,
      public_key: `RSA ${serverKey.asymmetricKeyDetails.modulusLength} біт, SHA-256(SPKI) ${K.keyFingerprint(serverKey)}`,
      certificate: sh.certificate ? 'X.509 (PEM) — бонус' : 'немає (базовий варіант: лише публічний ключ)',
    });
    if (sh.certificate) {
      let cert;
      try { cert = new crypto.X509Certificate(sh.certificate); } catch { throw new ProtocolError('bad_certificate', 'сертифікат не розібрано'); }
      log.info('сертифікат сервера (X.509)', {
        subject: cert.subject.replace(/\n/g, ', '),
        issuer: cert.issuer.replace(/\n/g, ', '),
        valid: `${cert.validFrom} — ${cert.validTo}`,
        fingerprint256: cert.fingerprint256,
        'самопідписаний': cert.verify(cert.publicKey) ? 'так, підпис коректний' : 'ні',
      });
      if (!K.sameKey(cert.publicKey, serverKey)) {
        throw new ProtocolError('certificate_key_mismatch', 'public_key із server_hello НЕ збігається з ключем у сертифікаті — можлива підміна (MITM)');
      }
      log.ok('ключ із сертифіката збігається з public_key сервера');
    }

    // Крок 3. Автентифікація в CA — пропускається в базовому варіанті
    log.step(3, 'пропущено (базовий варіант): перевірка сертифіката в центрі сертифікації не виконується');

    // Крок 4. premaster: 48 випадкових байтів, зашифровані RSA-OAEP(SHA-256) публічним ключем сервера
    const premaster = K.random(48);
    const encrypted = K.rsaEncrypt(sh.public_key, premaster);
    transcript.push(transport.send({ type: 'premaster', encrypted_premaster: encrypted.toString('base64') }));
    log.step(4, '→ premaster (RSA-OAEP, SHA-256)', { premaster: log.frag(premaster), encrypted_premaster: log.frag(encrypted) });

    // Крок 5. Ключі сеансу: HKDF(premaster, client_random‖server_random)
    const keys = K.deriveKeys(premaster, clientRandom, serverRandom);
    log.step(5, 'ключі сеансу (HKDF-SHA256)', describeKeys(keys, log.frag));

    // Крок 6. finished: «готовий» + verify_data = HMAC(master, label‖transcript_hash), шифрується AES-256-GCM
    const channel = new SecureChannel({ sendKey: keys.client_write_key, sendIv: keys.client_iv, recvKey: keys.server_write_key, recvIv: keys.server_iv });
    const thash = K.transcriptHash(transcript);
    let vd = K.verifyData(keys.master, 'client finished', thash);
    if (opts.corruptFinished) {
      vd = Buffer.from(vd); vd[0] ^= 0xff;
      log.warn('ТЕСТ: verify_data навмисно зіпсовано (--bad-finished)');
    }
    const cf = channel.seal('finished', { message: 'готовий', label: 'client finished', verify_data: vd.toString('hex') });
    transcript.push(transport.send(cf));
    log.step(6, '→ finished «готовий» (зашифровано AES-256-GCM)', { transcript_hash: log.frag(thash), verify_data: log.frag(vd), seq: cf.seq });

    const { msg: sf } = await queue.next('finished');
    const p = channel.open(sf);
    const expected = K.verifyData(keys.master, 'server finished', K.transcriptHash(transcript));
    if (!K.safeEqualHex(p.verify_data, expected)) throw new ProtocolError('bad_finished', 'finished сервера не відповідає transcript hash');
    log.step(6, `← finished сервера «${p.message}» перевірено`, { verify_data: log.frag(expected) });

    // Крок 7. Рукостискання завершено
    log.step(7, 'рукостискання завершено — далі тільки AES-256-GCM на ключах сеансу');
    return new Session({ role: 'client', transport, queue, channel, keys, log, info: { clientRandom, serverRandom, cipherSuite: sh.cipher_suite } });
  });
}

// ===== Сервер =====
async function serverHandshake(transport, opts) {
  const log = opts.log || createLogger('server', { silent: true });
  const { privateKey, publicKey, certificate } = opts.keys;
  const queue = new MessageQueue(transport);
  const transcript = [];

  return guarded(transport, log, async () => {
    // Крок 1
    const { msg: ch, raw: chRaw } = await queue.next('client_hello');
    transcript.push(chRaw);
    if (ch.version !== VERSION) throw new ProtocolError('protocol_version', `непідтримувана версія ${ch.version}`);
    const clientRandom = readRandom(ch.client_random, 'client_random');
    const suite = (Array.isArray(ch.cipher_suites) ? ch.cipher_suites : []).find((s) => CIPHER_SUITES.includes(s));
    if (!suite) throw new ProtocolError('handshake_failure', 'немає спільного набору шифрів');
    log.step(1, '← client_hello', { version: ch.version, client_random: log.frag(clientRandom), cipher_suites: ch.cipher_suites.join(', ') });

    // Крок 2
    const serverRandom = K.random(32);
    const sh = { type: 'server_hello', server_random: serverRandom.toString('hex'), cipher_suite: suite, public_key: publicKey, ...(certificate ? { certificate } : {}) };
    transcript.push(transport.send(sh));
    log.step(2, '→ server_hello', {
      server_random: log.frag(serverRandom),
      cipher_suite: suite,
      public_key: `RSA 2048 біт, SHA-256(SPKI) ${K.keyFingerprint(publicKey)}`,
      certificate: certificate ? 'X.509 самопідписаний (бонус)' : 'не надсилається (базовий варіант)',
    });

    // Крок 3
    log.step(3, 'пропущено (базовий варіант): клієнт не перевіряє сертифікат у CA');

    // Крок 4
    const { msg: pm, raw: pmRaw } = await queue.next('premaster');
    transcript.push(pmRaw);
    const encrypted = Buffer.from(pm.encrypted_premaster || '', 'base64');
    let premaster;
    try { premaster = K.rsaDecrypt(privateKey, encrypted); } catch { throw new ProtocolError('decrypt_error', 'не вдалося розшифрувати premaster (RSA-OAEP)'); }
    if (premaster.length !== 48) throw new ProtocolError('decrypt_error', 'premaster має бути 48 байтів');
    log.step(4, '← premaster розшифровано приватним ключем', { encrypted_premaster: log.frag(encrypted), premaster: log.frag(premaster) });

    // Крок 5
    const keys = K.deriveKeys(premaster, clientRandom, serverRandom);
    log.step(5, 'ключі сеансу (HKDF-SHA256)', describeKeys(keys, log.frag));

    // Крок 6: спершу перевіряємо finished клієнта, потім надсилаємо свій
    const channel = new SecureChannel({ sendKey: keys.server_write_key, sendIv: keys.server_iv, recvKey: keys.client_write_key, recvIv: keys.client_iv });
    const { msg: cf, raw: cfRaw } = await queue.next('finished');
    const p = channel.open(cf);
    const thash = K.transcriptHash(transcript);
    const expected = K.verifyData(keys.master, 'client finished', thash);
    if (!K.safeEqualHex(p.verify_data, expected)) {
      throw new ProtocolError('bad_finished', 'finished клієнта не збігається з transcript hash сервера — повідомлення рукостискання змінено (MITM?) або verify_data невірний');
    }
    log.step(6, `← finished клієнта «${p.message}» перевірено`, { transcript_hash: log.frag(thash), verify_data: log.frag(expected) });
    transcript.push(cfRaw);
    const svd = K.verifyData(keys.master, 'server finished', K.transcriptHash(transcript));
    const sf = channel.seal('finished', { message: 'готовий', label: 'server finished', verify_data: svd.toString('hex') });
    transport.send(sf);
    log.step(6, '→ finished «готовий» (зашифровано AES-256-GCM)', { verify_data: log.frag(svd), seq: sf.seq });

    // Крок 7
    log.step(7, 'рукостискання завершено — далі тільки AES-256-GCM на ключах сеансу');
    return new Session({ role: 'server', transport, queue, channel, keys, log, info: { clientRandom, serverRandom, cipherSuite: suite } });
  });
}

module.exports = { clientHandshake, serverHandshake, Session, MessageQueue };
