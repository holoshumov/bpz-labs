// Логіка зловмисника посередині (для mitm.js і тестів). Фільтри c2s/s2c: (msg, raw) → масив сирих повідомлень.
// Режими:
//   keyswap       — підміняє public_key сервера своїм, прибирає сертифікат, розшифровує premaster
//                   і перешифровує його справжнім ключем сервера → обидві сторони мають однакові ключі,
//                   але transcript відрізняється → finished не сходиться
//   keyswap-cert  — те саме, але сертифікат залишає → клієнт ловить розбіжність ключа вже на кроці 2 (бонус X.509)
//   tamper        — змінює 1 байт шифротексту першого data-повідомлення клієнта → AES-GCM відхиляє
//   replay        — надсилає перше data-повідомлення клієнта двічі → відхилено за номером послідовності
const { generateRsaKeyPair, rsaEncrypt, rsaDecrypt, keyFingerprint } = require('./crypto');

const MODES = ['keyswap', 'keyswap-cert', 'tamper', 'replay', 'pass'];

function createMitm(mode, log, { keys } = {}) {
  if (!MODES.includes(mode)) throw new Error(`невідомий режим ${mode}; доступні: ${MODES.join(', ')}`);
  const swap = mode.startsWith('keyswap');
  const mitmKeys = swap ? (keys || generateRsaKeyPair()) : null;
  let realServerKey = null;
  let clientData = 0;

  return {
    s2c(msg, raw) {
      log.info(`S→C ${msg.type}`);
      if (swap && msg.type === 'server_hello') {
        realServerKey = msg.public_key;
        const forged = { ...msg, public_key: mitmKeys.publicKey };
        if (mode === 'keyswap') delete forged.certificate;
        log.warn('server_hello: публічний ключ сервера ПІДМІНЕНО ключем MITM', {
          'справжній ключ': keyFingerprint(realServerKey), 'ключ MITM': keyFingerprint(mitmKeys.publicKey),
          certificate: msg.certificate ? (mode === 'keyswap' ? 'вирізано' : 'залишено без змін') : 'не було',
        });
        return [JSON.stringify(forged)];
      }
      return [raw];
    },
    c2s(msg, raw) {
      log.info(`C→S ${msg.type}${msg.seq !== undefined ? ` seq=${msg.seq}` : ''}`);
      if (swap && msg.type === 'premaster') {
        const premaster = rsaDecrypt(mitmKeys.privateKey, Buffer.from(msg.encrypted_premaster, 'base64'));
        log.warn('premaster розшифровано ключем MITM і перешифровано справжнім ключем сервера', { premaster: log.frag(premaster) });
        return [JSON.stringify({ ...msg, encrypted_premaster: rsaEncrypt(realServerKey, premaster).toString('base64') })];
      }
      if (msg.type === 'data') {
        clientData += 1;
        if (mode === 'tamper' && clientData === 1) {
          const ct = Buffer.from(msg.ct, 'base64');
          const before = ct[0];
          ct[0] ^= 0x01;
          log.warn(`data seq=${msg.seq}: змінено 1 байт шифротексту (0x${before.toString(16).padStart(2, '0')} → 0x${ct[0].toString(16).padStart(2, '0')})`);
          return [JSON.stringify({ ...msg, ct: ct.toString('base64') })];
        }
        if (mode === 'replay' && clientData === 1) {
          log.warn(`data seq=${msg.seq}: повідомлення перехоплено й надіслано ПОВТОРНО (replay)`);
          return [raw, raw];
        }
      }
      return [raw];
    },
  };
}

module.exports = { createMitm, MODES };
