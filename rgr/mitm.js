#!/usr/bin/env node
// Проксі-зловмисник між клієнтом і сервером для негативних сценаріїв.
// node mitm.js --mode keyswap|keyswap-cert|tamper|replay [--listen 9443] [--target 127.0.0.1:8443]
// Клієнт підключається до --listen, думаючи, що це сервер.
const net = require('net');
const { parseArgs } = require('./src/args');
const { createLogger } = require('./src/log');
const { FrameDecoder, encodeFrame } = require('./src/protocol');
const { createMitm, MODES } = require('./src/mitm-core');

const args = parseArgs(process.argv.slice(2), { listen: 9443, target: '127.0.0.1:8443', mode: 'pass' });
const log = createLogger('mitm', { verbose: Boolean(args.verbose) });
if (!MODES.includes(args.mode)) { log.err(`режим: ${MODES.join(' | ')}`); process.exit(2); }
const [thost, tport] = args.target.split(':');

const server = net.createServer((client) => {
  const mitm = createMitm(args.mode, log);
  const upstream = net.connect(Number(tport), thost);
  log.info(`клієнт ${client.remoteAddress}:${client.remotePort} → перехоплюю і з'єднуюсь із сервером ${args.target}`);
  const relay = (from, to, filter) => {
    const dec = new FrameDecoder();
    from.on('data', (chunk) => {
      for (const raw of dec.push(chunk)) {
        for (const out of filter(JSON.parse(raw), raw)) to.write(encodeFrame(out));
      }
    });
    from.on('end', () => to.end());
    from.on('error', () => to.destroy());
  };
  relay(client, upstream, mitm.c2s);
  relay(upstream, client, mitm.s2c);
  client.on('close', () => log.info("з'єднання клієнта закрито"));
});

server.listen(Number(args.listen), '127.0.0.1', () => log.warn(`MITM-проксі (${args.mode}) слухає 127.0.0.1:${args.listen} → ${args.target}`));
const stop = () => { server.close(); process.exit(0); };
process.on('SIGINT', stop);
process.on('SIGTERM', stop);
