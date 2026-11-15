// Транспорт за інтерфейсом: send(msg) → raw, close(), події 'message'(msg, raw) і 'close'.
// SocketTransport — TCP (net.Socket) з кадруванням; memoryPair — пара в пам'яті для тестів
// (з фільтрами c2s/s2c, через які можна імітувати MITM, псування чи повтор пакетів).
// Розширений варіант (кілька нод, маршрутизація) зможе додати власний транспорт із тим самим інтерфейсом.
const { EventEmitter } = require('events');
const { encodeFrame, FrameDecoder, parseMessage } = require('./protocol');

class Transport extends EventEmitter {
  constructor() {
    super();
    this.closed = false;
  }

  // Повертає сирий JSON — саме він іде в transcript hash.
  send(msg) {
    const raw = JSON.stringify(msg);
    this.sendRaw(raw);
    return raw;
  }

  _deliver(raw) {
    let msg;
    try { msg = parseMessage(raw); } catch (e) { this.emit('protocol_error', e); return; }
    this.emit('message', msg, raw);
  }

  _markClosed() {
    if (this.closed) return;
    this.closed = true;
    this.emit('close');
  }
}

class SocketTransport extends Transport {
  constructor(socket) {
    super();
    this.socket = socket;
    this.peer = `${socket.remoteAddress}:${socket.remotePort}`;
    const decoder = new FrameDecoder();
    socket.on('data', (chunk) => {
      let frames;
      try { frames = decoder.push(chunk); } catch (e) {
        this.emit('protocol_error', e);
        socket.destroy();
        return;
      }
      for (const raw of frames) this._deliver(raw);
    });
    socket.on('error', (e) => this.emit('transport_error', e));
    socket.on('close', () => this._markClosed());
  }

  sendRaw(raw) {
    if (!this.closed && !this.socket.destroyed && this.socket.writable) this.socket.write(encodeFrame(raw));
  }

  close() {
    if (!this.socket.destroyed) this.socket.end();
  }
}

class MemoryTransport extends Transport {
  sendRaw(raw) {
    if (this.closed) return;
    const peer = this.peer;
    // setImmediate: асинхронна доставка в порядку відправлення (як у TCP)
    setImmediate(() => {
      if (peer.closed) return;
      const out = this.filter(JSON.parse(raw), raw) || [];
      for (const r of out) peer._deliver(r);
    });
  }

  close() {
    setImmediate(() => { this._markClosed(); this.peer._markClosed(); });
  }
}

const pass = (msg, raw) => [raw];

function memoryPair({ c2s = pass, s2c = pass } = {}) {
  const client = new MemoryTransport();
  const server = new MemoryTransport();
  client.peer = server; server.peer = client;
  client.filter = c2s; server.filter = s2c;
  client.peerName = 'memory:server'; server.peerName = 'memory:client';
  return { client, server };
}

module.exports = { Transport, SocketTransport, MemoryTransport, memoryPair };
