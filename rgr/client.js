#!/usr/bin/env node
// Клієнт: рукостискання, потім чат. Рядок → зашифроване повідомлення; /send <шлях> — передати файл; /quit — вихід.
// node client.js [--host 127.0.0.1] [--port 8443] [--verbose] [--bad-finished]
// Якщо stdin не термінал (демо), рядки читаються з конвеєра, клієнт чекає всі підтвердження і завершується.
const fs = require('fs');
const net = require('net');
const readline = require('readline');
const { parseArgs } = require('./src/args');
const { createLogger } = require('./src/log');
const { SocketTransport } = require('./src/transport');
const { clientHandshake } = require('./src/handshake');
const { filePayload } = require('./src/app');

const args = parseArgs(process.argv.slice(2), { port: 8443, host: '127.0.0.1' });
const log = createLogger('client', { verbose: Boolean(args.verbose) });
const interactive = process.stdin.isTTY;

const lines = [];
let inputDone = false;
let session = null;
let pending = 0;
let busy = false;

const rl = readline.createInterface({ input: process.stdin });
rl.on('line', (l) => { lines.push(l); pump(); });
rl.on('close', () => { inputDone = true; pump(); });

function finish(code = 0) {
  process.exitCode = code;
  if (session) session.close();
  setTimeout(() => process.exit(code), 200).unref();
}

function pump() {
  if (!session || busy) return;
  busy = true;
  while (lines.length) {
    const line = lines.shift().trim();
    if (!line) continue;
    if (line === '/quit') { finish(0); return; }
    if (line.startsWith('/send ')) {
      const file = line.slice(6).trim();
      try {
        const p = filePayload(file);
        log.info(`📄 надсилаю файл «${p.name}»`, { size: `${p.size} Б`, sha256: p.sha256 });
        session.send(p);
        pending++;
      } catch (e) { log.err(`файл не надіслано: ${e.message}`); }
      continue;
    }
    log.info(`💬 я: ${line}`);
    session.send({ kind: 'chat', text: line });
    pending++;
  }
  busy = false;
  if (inputDone && pending === 0 && !interactive) { log.info('усі повідомлення підтверджено, завершую'); finish(0); }
}

const socket = net.connect(Number(args.port), args.host);
const transport = new SocketTransport(socket);
transport.on('transport_error', (e) => { log.err(`TCP: ${e.message}`); finish(1); });

socket.once('connect', async () => {
  log.info(`з'єднано з ${args.host}:${args.port}`);
  try {
    session = await clientHandshake(transport, { log, corruptFinished: Boolean(args.badFinished) });
  } catch {
    finish(1);
    return;
  }
  session.on('data', (p) => {
    if (p.kind === 'ack') { log.ok(`підтвердження: ${p.text}`); pending--; }
    else if (p.kind === 'file_ack') {
      (p.ok ? log.ok : log.err)(`сервер ${p.ok ? 'зберіг' : 'НЕ прийняв'} файл «${p.name}»`, { 'sha256 на сервері': p.sha256, saved_as: p.saved_as || '—' });
      pending--;
    } else if (p.kind === 'chat') log.ok(`💬 сервер: ${p.text}`);
    pump();
  });
  session.on('fail', () => finish(1));
  session.on('close', () => { if (!session.failed) log.info("з'єднання закрито"); finish(process.exitCode || 0); });
  session.start();
  if (interactive) log.info('введіть повідомлення; /send <файл> — передати файл; /quit — вихід');
  pump();
});
