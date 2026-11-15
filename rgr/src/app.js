// Застосунковий рівень поверх захищеного каналу: чат і передача текстового файлу.
// Корисне навантаження всередині data (уже після розшифрування):
//   { kind:'chat', text }            { kind:'ack', seq, text }
//   { kind:'file', name, size, sha256, content(base64) }   { kind:'file_ack', name, sha256, ok, saved_as }
const fs = require('fs');
const path = require('path');
const { sha256 } = require('./crypto');

const MAX_FILE = 8 * 1024 * 1024;

function filePayload(filePath) {
  const content = fs.readFileSync(filePath);
  if (content.length > MAX_FILE) throw new Error(`файл більший за ${MAX_FILE} Б`);
  return { kind: 'file', name: path.basename(filePath), size: content.length, sha256: sha256(content), content: content.toString('base64') };
}

// Серверна обробка сеансу: відповідь на чат, збереження файлу в received/ з перевіркою SHA-256.
function serveSession(session, { log, receivedDir, onChat }) {
  session.on('data', (p, msg) => {
    if (p.kind === 'chat') {
      log.ok(`💬 клієнт: ${p.text}`);
      if (onChat) onChat(session, p);
      session.send({ kind: 'ack', seq: msg.seq, text: `сервер отримав «${p.text}»` });
    } else if (p.kind === 'file') {
      const content = Buffer.from(p.content || '', 'base64');
      const actual = sha256(content);
      const ok = actual === p.sha256 && content.length === p.size;
      fs.mkdirSync(receivedDir, { recursive: true });
      const safeName = path.basename(String(p.name)).replace(/[^\w.\-а-яА-ЯіІїЇєЄґҐ]/g, '_') || 'file.txt';
      const savedAs = path.join(receivedDir, `${Date.now()}-${safeName}`);
      if (ok) fs.writeFileSync(savedAs, content);
      (ok ? log.ok : log.err)(`📄 файл «${p.name}» ${ok ? 'отримано й збережено' : 'ПОШКОДЖЕНО'}`, {
        size: `${content.length} Б`, 'sha256 заявлений': p.sha256, 'sha256 обчислений': actual, saved_as: ok ? path.relative(process.cwd(), savedAs) : '—',
      });
      session.send({ kind: 'file_ack', name: p.name, sha256: actual, ok, saved_as: ok ? path.basename(savedAs) : null });
    }
  });
}

module.exports = { filePayload, serveSession, MAX_FILE };
