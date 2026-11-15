const { once } = require('events');
const { memoryPair } = require('../src/transport');
const { clientHandshake, serverHandshake } = require('../src/handshake');
const { createLogger } = require('../src/log');
const K = require('../src/crypto');

const SERVER_KEYS = { ...K.generateRsaKeyPair(), certificate: null };
const silent = (role) => createLogger(role, { silent: true });

// Повне рукостискання в одному процесі. Повертає результати обох сторін (успіх або помилка).
async function handshake({ filters, keys = SERVER_KEYS, client = {} } = {}) {
  const t = memoryPair(filters);
  const [c, s] = await Promise.allSettled([
    clientHandshake(t.client, { log: silent('client'), ...client }),
    serverHandshake(t.server, { keys, log: silent('server') }),
  ]);
  return { c, s, t };
}

const nextEvent = (emitter, name, ms = 2000) => Promise.race([
  once(emitter, name).then((a) => a[0]),
  new Promise((_, rej) => setTimeout(() => rej(new Error(`timeout waiting for ${name}`)), ms).unref()),
]);

module.exports = { SERVER_KEYS, silent, handshake, nextEvent };
