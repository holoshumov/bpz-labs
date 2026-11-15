// Захищений канал після рукостискання: AES-256-GCM, окремий ключ і IV для кожного напрямку,
// лічильник послідовності (seq) — захист від повтору й перестановки, AAD = "тип|seq".
const { aesGcmEncrypt, aesGcmDecrypt, nonceFor } = require('./crypto');
const { ProtocolError } = require('./protocol');

class SecureChannel {
  constructor({ sendKey, sendIv, recvKey, recvIv }) {
    Object.assign(this, { sendKey, sendIv, recvKey, recvIv });
    this.sendSeq = 0;
    this.recvSeq = 0;
  }

  seal(type, payload) {
    const seq = this.sendSeq++;
    const aad = Buffer.from(`${type}|${seq}`);
    const { ct, tag } = aesGcmEncrypt(this.sendKey, nonceFor(this.sendIv, seq), Buffer.from(JSON.stringify(payload), 'utf8'), aad);
    return { type, seq, ct: ct.toString('base64'), tag: tag.toString('hex') };
  }

  open(msg) {
    // 1) номер послідовності: кожен seq приймається рівно один раз і по порядку
    if (msg.seq !== this.recvSeq) {
      throw new ProtocolError('bad_seq', `seq=${msg.seq}, очікувався seq=${this.recvSeq} — повтор (replay) або перестановка повідомлення, відхилено`);
    }
    // 2) AES-GCM перевіряє тег: змінений шифротекст, тип чи seq (вони в AAD і nonce) → помилка автентифікації
    const aad = Buffer.from(`${msg.type}|${msg.seq}`);
    let plain;
    try {
      plain = aesGcmDecrypt(this.recvKey, nonceFor(this.recvIv, msg.seq), Buffer.from(msg.ct || '', 'base64'), Buffer.from(msg.tag || '', 'hex'), aad);
    } catch (e) {
      throw new ProtocolError('bad_record_mac', `AES-GCM відхилив повідомлення seq=${msg.seq}: ${e.message}`);
    }
    this.recvSeq++;
    return JSON.parse(plain.toString('utf8'));
  }
}

module.exports = { SecureChannel };
