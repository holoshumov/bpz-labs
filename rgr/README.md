# РГР — імітація TLS/SSL-рукостискання (базовий варіант)

БПЗ 2026, ст. гр. ІМ-31 Голошумов Владислав Михайлович.
Node.js ≥ 18, лише вбудовані модулі `crypto` і `net`, сторонніх залежностей немає (`npm install` не потрібен).

| Крок | Що відбувається | Де в коді |
|---|---|---|
| 1 | `client_hello`: `client_random` (32 Б), версія, список шифрів | `src/handshake.js` → `clientHandshake` |
| 2 | `server_hello`: `server_random` (32 Б), обраний шифр, публічний ключ RSA-2048 (бонус: X.509) | `serverHandshake` |
| 3 | перевірка в CA — **пропущено (базовий варіант)**; бонус: ключ сертифіката = ключ сервера | `clientHandshake` |
| 4 | `premaster` (48 Б), зашифрований RSA-OAEP(SHA-256) | `src/crypto.js` → `rsaEncrypt/rsaDecrypt` |
| 5 | `master = HKDF-SHA256(premaster, client_random‖server_random, "bpz master")` → ключі й IV для кожного напрямку | `deriveKeys` |
| 6 | `finished` «готовий» + `verify_data = HMAC(master, label‖SHA-256(transcript))`, AES-256-GCM | `verifyData`, `SecureChannel` |
| 7 | захищений канал: AES-256-GCM, nonce = IV ⊕ seq, AAD = `тип|seq`, контроль seq | `src/channel.js` |

## Запуск

```bash
npm test                 # 13 тестів node:test (рукостискання, канал, 4 негативні сценарії)
npm run demo             # демо: базовий, з X.509, 2 клієнти, --verbose → evidence/demo-*.log
npm run negative         # MITM, псування байта, replay, невірний finished → evidence/neg*.log
npm run cert             # (бонус) keys/server.key + keys/server.crt через openssl
```

Інтерактивно — два термінали:

```bash
node server.js --no-cert            # базовий варіант (без --no-cert, якщо є keys/server.crt, — з сертифікатом)
node client.js                      # пишіть повідомлення; /send samples/message.txt — файл; /quit — вихід
```

Опції: `--port 8443`, `--host 127.0.0.1`, `--verbose` (повні значення random/premaster/ключів),
у клієнта `--bad-finished` (навмисно зіпсований finished). Сервер обслуговує кількох клієнтів, у кожного свій сеанс;
рядок, набраний у консолі сервера, шифрується й надсилається всім клієнтам.

MITM-проксі: `node mitm.js --mode keyswap|keyswap-cert|tamper|replay --listen 9443 --target 127.0.0.1:8443`,
клієнт тоді: `node client.js --port 9443`.

## Структура

```
src/protocol.js    версія, набір шифрів, кадрування (4 Б довжини + JSON), ProtocolError
src/transport.js   інтерфейс транспорту: TCP (SocketTransport) і пара в пам'яті для тестів
src/crypto.js      RSA-OAEP, HKDF, AES-256-GCM, nonce, transcript hash, verify_data
src/handshake.js   стан-машина рукостискання (обидві ролі) + Session
src/channel.js     захищений канал (seq, nonce, AAD)
src/app.js         чат і передача файлу (SHA-256 на обох сторонах, збереження в received/)
src/mitm-core.js   логіка атак для mitm.js і тестів
server.js, client.js, mitm.js — CLI
scripts/           gen-cert.sh, demo.sh, negative.sh
test/              node:test
evidence/          логи демо, негативних сценаріїв і npm test
```

Архітектура готова до розширеного варіанту: протокол, транспорт і ролі розділені (нода = `clientHandshake`/`serverHandshake`
над будь-яким транспортом із `send/close/'message'`), тож root-CA, кілька нод, обмеження розміру пакета й маршрутизацію
можна додати без переписування рукостискання.

Документи: [NOTES.md](NOTES.md) (теорія + питання), [REPORT_DRAFT.md](REPORT_DRAFT.md), [SCREENSHOTS_CHECKLIST.md](SCREENSHOTS_CHECKLIST.md), [VIDEO_PLAN.md](VIDEO_PLAN.md).
