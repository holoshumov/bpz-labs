#!/usr/bin/env node
// Сервер: на кожне TCP-з'єднання — окреме рукостискання і окремий сеанс зі своїми ключами.
// node server.js [--port 8443] [--host 127.0.0.1] [--verbose] [--no-cert]
// Якщо є keys/server.key і keys/server.crt (scripts/gen-cert.sh) — надсилає X.509-сертифікат (бонус),
// інакше генерує пару RSA-2048 при старті й надсилає лише публічний ключ (базовий варіант).
const fs = require('fs');
const net = require('net');
const path = require('path');
const readline = require('readline');
const crypto = require('crypto');
const { parseArgs } = require('./src/args');
const { createLogger } = require('./src/log');
const { SocketTransport } = require('./src/transport');
const { serverHandshake } = require('./src/handshake');
const { serveSession } = require('./src/app');
const K = require('./src/crypto');

const args = parseArgs(process.argv.slice(2), { port: 8443, host: '127.0.0.1' });
const verbose = Boolean(args.verbose);
const log = createLogger('server', { verbose });

function loadKeys() {
  const keyFile = path.join(__dirname, 'keys', 'server.key');
  const certFile = path.join(__dirname, 'keys', 'server.crt');
  if (!args.noCert && fs.existsSync(keyFile) && fs.existsSync(certFile)) {
    const privateKey = fs.readFileSync(keyFile, 'utf8');
    const certificate = fs.readFileSync(certFile, 'utf8');
    const publicKey = crypto.createPublicKey(privateKey).export({ type: 'spki', format: 'pem' });
    const cert = new crypto.X509Certificate(certificate);
    log.info('завантажено keys/server.key + keys/server.crt (бонус: X.509)', { subject: cert.subject.replace(/\n/g, ', '), fingerprint256: cert.fingerprint256 });
    return { privateKey, publicKey, certificate };
  }
  const t = Date.now();
  const kp = K.generateRsaKeyPair();
  log.info(`згенеровано пару ключів RSA-2048 за ${Date.now() - t} мс (базовий варіант, сертифіката немає)`, { public_key: K.keyFingerprint(kp.publicKey) });
  return { privateKey: kp.privateKey, publicKey: kp.publicKey, certificate: null };
}

const keys = loadKeys();
const receivedDir = path.join(__dirname, 'received');
const sessions = new Set();
let counter = 0;

const server = net.createServer(async (socket) => {
  const id = ++counter;
  const slog = createLogger('server', { verbose, tag: `#${id}` });
  const transport = new SocketTransport(socket);
  transport.on('transport_error', (e) => slog.err(`TCP: ${e.message}`));
  slog.info(`нове з'єднання від ${transport.peer}`);
  let session;
  try {
    session = await serverHandshake(transport, { keys, log: slog });
  } catch {
    return; // причину вже залоговано, alert надіслано, з'єднання закрито
  }
  sessions.add(session);
  serveSession(session, { log: slog, receivedDir });
  session.on('fail', () => sessions.delete(session));
  session.on('close', () => { sessions.delete(session); slog.info("з'єднання закрито"); });
  session.start();
});

server.listen(Number(args.port), args.host, () => {
  log.info(`слухаю ${args.host}:${args.port} (Ctrl+C — вихід${process.stdin.isTTY ? '; рядок у консолі — повідомлення всім клієнтам' : ''})`);
});

// Інтерактивно: те, що набрано в консолі сервера, шифрується і надсилається всім клієнтам
if (process.stdin.isTTY) {
  const rl = readline.createInterface({ input: process.stdin });
  rl.on('line', (text) => {
    if (!text.trim()) return;
    if (!sessions.size) return log.warn('немає підключених клієнтів');
    for (const s of sessions) s.send({ kind: 'chat', from: 'server', text });
  });
}

const stop = () => { log.info('зупинка'); for (const s of sessions) s.close(); server.close(() => process.exit(0)); setTimeout(() => process.exit(0), 500).unref(); };
process.on('SIGINT', stop);
process.on('SIGTERM', stop);
