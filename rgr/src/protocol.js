// Формати повідомлень і кадрування (framing) для імітації TLS-рукостискання.
// Кадр = 4 байти довжини (uint32 big-endian) + JSON у UTF-8. Кожне повідомлення має поле `type`.
const VERSION = 'BPZ-TLS/1.0';

// Єдиний «набір шифрів» базового варіанту: обмін ключем RSA-OAEP(SHA-256), KDF HKDF-SHA256, канал AES-256-GCM.
const CIPHER_SUITES = ['BPZ_RSA_OAEP_SHA256_WITH_AES_256_GCM_HKDF_SHA256'];

const MAX_FRAME = 16 * 1024 * 1024; // 16 МБ — захист від «нескінченного» кадру

// Типи повідомлень (крок → напрям):
//  1 client_hello  C→S  { version, client_random(hex 32 Б), cipher_suites[] }
//  2 server_hello  S→C  { server_random(hex 32 Б), cipher_suite, public_key(PEM), certificate?(PEM) }
//  4 premaster     C→S  { encrypted_premaster(base64, RSA-OAEP) }
//  6 finished      обидва { seq, ct, tag } — зашифроване «готовий» + verify_data
//  7 data          обидва { seq, ct, tag } — дані застосунку (чат, файл)
//  - alert         обидва { reason } — фатальна помилка, з'єднання закривається
const TYPES = ['client_hello', 'server_hello', 'premaster', 'finished', 'data', 'alert'];

class ProtocolError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'ProtocolError';
    this.code = code;
  }
}

function encodeFrame(raw) {
  const body = Buffer.from(raw, 'utf8');
  const header = Buffer.alloc(4);
  header.writeUInt32BE(body.length);
  return Buffer.concat([header, body]);
}

// Потоковий декодер: TCP не зберігає межі повідомлень, тому збираємо байти, доки не прийде цілий кадр.
class FrameDecoder {
  constructor() { this.buf = Buffer.alloc(0); }

  push(chunk) {
    this.buf = Buffer.concat([this.buf, chunk]);
    const frames = [];
    while (this.buf.length >= 4) {
      const len = this.buf.readUInt32BE(0);
      if (len > MAX_FRAME) throw new ProtocolError('frame_too_large', `кадр ${len} Б більший за ліміт ${MAX_FRAME} Б`);
      if (this.buf.length < 4 + len) break;
      frames.push(this.buf.subarray(4, 4 + len).toString('utf8'));
      this.buf = this.buf.subarray(4 + len);
    }
    return frames;
  }
}

function parseMessage(raw) {
  let msg;
  try { msg = JSON.parse(raw); } catch { throw new ProtocolError('bad_message', 'кадр не є JSON'); }
  if (!msg || typeof msg.type !== 'string') throw new ProtocolError('bad_message', 'повідомлення без поля type');
  if (!TYPES.includes(msg.type)) throw new ProtocolError('bad_message', `невідомий тип повідомлення ${msg.type}`);
  return msg;
}

module.exports = { VERSION, CIPHER_SUITES, MAX_FRAME, TYPES, ProtocolError, encodeFrame, FrameDecoder, parseMessage };
