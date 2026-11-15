# Чернетка звіту РГР

---

<div align="center">

МІНІСТЕРСТВО ОСВІТИ І НАУКИ УКРАЇНИ
НАЦІОНАЛЬНИЙ ТЕХНІЧНИЙ УНІВЕРСИТЕТ УКРАЇНИ
«КИЇВСЬКИЙ ПОЛІТЕХНІЧНИЙ ІНСТИТУТ імені ІГОРЯ СІКОРСЬКОГО»
Факультет інформатики та обчислювальної техніки

**РОЗРАХУНКОВО-ГРАФІЧНА РОБОТА**
з дисципліни «Безпека програмного забезпечення»

на тему: **«Імітація TLS/SSL-рукостискання»**
(базовий варіант)

Виконав: студент групи ІМ-31
Голошумов Владислав Михайлович

Перевірив: ____________________

Київ — 2026

</div>

---

## Зміст

1. Теоретична частина
2. Практична реалізація
   2.1. Архітектура і формат повідомлень
   2.2. Крок 1 — ініціювання клієнтом
   2.3. Крок 2 — відповідь сервера
   2.4. Крок 3 — автентифікація
   2.5. Крок 4 — обмін premaster
   2.6. Крок 5 — генерація ключів сеансу
   2.7. Крок 6 — готовність клієнта і сервера
   2.8. Крок 7 — завершення рукостискання і захищений канал
   2.9. Передача повідомлень чату і текстового файлу
3. Тестування
4. Висновки
5. Список літератури

---

## 1. Теоретична частина

**TLS і його задачі.** Transport Layer Security — протокол захисту даних поверх TCP. Він забезпечує конфіденційність
(симетричне шифрування), цілісність (MAC або AEAD) і автентифікацію сервера (сертифікат X.509 у PKI). Перед обміном
даними сторони виконують рукостискання (handshake), під час якого домовляються про алгоритми і виробляють спільні
ключі сеансу, не передаючи їх відкрито.

**Рукостискання TLS 1.2 з обміном ключем RSA.** Клієнт надсилає ClientHello з 32-байтовим випадковим числом і списком
шифрів; сервер відповідає ServerHello зі своїм випадковим числом, обраним шифром і сертифікатом. Клієнт перевіряє
сертифікат, генерує 48-байтовий premaster secret, шифрує його публічним ключем сервера (ClientKeyExchange). Обидві
сторони обчислюють master secret з premaster і двох random, з нього — ключі шифрування та MAC для кожного напрямку.
Повідомлення Finished містить MAC від усіх повідомлень рукостискання; його правильність доводить, що сторони бачили
однаковий обмін і мають однакові ключі.

**Відмінності TLS 1.3.** Видалено статичний обмін RSA — лише ефемерний (EC)DHE, що дає пряму секретність (forward
secrecy); рукостискання скорочено до 1-RTT, сертифікат передається вже зашифрованим; як KDF використовується HKDF;
дозволено лише AEAD-шифри; прибрано стиснення, renegotiation, CBC-режими; з'явився 0-RTT.

**Асиметричне шифрування RSA-OAEP.** RSA спирається на складність факторизації. Схема доповнення OAEP (RFC 8017)
рандомізує шифротекст і захищає від атак на «підручниковий» RSA та від атак Блейхенбахера на PKCS#1 v1.5.

**KDF і HKDF.** Функція виведення ключів перетворює секрет нерівномірного розподілу на криптографічно стійкі ключі.
HKDF (RFC 5869) складається з етапів *extract* (HMAC(salt, IKM) → PRK) і *expand* (PRK + info → ключовий матеріал
потрібної довжини); різні значення `info` дають незалежні ключі.

**AES-GCM (AEAD).** Galois/Counter Mode (NIST SP 800-38D) поєднує шифрування AES у режимі лічильника з автентифікацією
GHASH. Результат — шифротекст і тег, що захищає цілісність шифротексту й додаткових автентифікованих даних (AAD).
Критична вимога — унікальність nonce для кожного повідомлення з тим самим ключем.

**X.509 і PKI.** Сертифікат X.509 (RFC 5280) зв'язує ім'я суб'єкта з публічним ключем і підписаний центром
сертифікації (CA). Довіра будується ланцюжком до кореневого CA, якому довіряє клієнт.

**Атаки і протидія.** *MITM* — посередник підміняє ключ сервера; протидія — автентифікація сервера сертифікатом і
перевірка Finished. *Replay* — повторне надсилання перехоплених повідомлень; протидія — номери послідовності, включені
в nonce і AAD. *Downgrade* — нав'язування слабшого шифру; протидія — включення списку шифрів у transcript, який
автентифікує Finished.

## 2. Практична реалізація

Мова — JavaScript (Node.js 24), використано лише вбудовані модулі `crypto` і `net`. Код:
https://github.com/holoshumov/bpz-labs/tree/main/rgr

### 2.1. Архітектура і формат повідомлень

| Модуль | Призначення |
|---|---|
| `src/protocol.js` | версія `BPZ-TLS/1.0`, набір шифрів, кадрування: 4 байти довжини + JSON |
| `src/transport.js` | інтерфейс транспорту: TCP і пара в пам'яті (для тестів і імітації атак) |
| `src/crypto.js` | RSA-OAEP, HKDF, AES-256-GCM, nonce, transcript hash, verify_data |
| `src/handshake.js` | стан-машина рукостискання для обох ролей, сеанс |
| `src/channel.js` | захищений канал: лічильники, nonce, AAD |
| `src/app.js` | чат і передача файлу |
| `server.js`, `client.js`, `mitm.js` | консольні програми |

Набір шифрів: `BPZ_RSA_OAEP_SHA256_WITH_AES_256_GCM_HKDF_SHA256`. Кожне повідомлення має поле `type`:
`client_hello`, `server_hello`, `premaster`, `finished`, `data`, `alert`. Протокол, транспорт і ролі розділено, що
дозволяє розширити роботу (кілька нод, root-CA, маршрутизація) без зміни рукостискання.

```js
// src/protocol.js — кадр: 4 байти довжини (big-endian) + JSON
function encodeFrame(raw) {
  const body = Buffer.from(raw, 'utf8');
  const header = Buffer.alloc(4);
  header.writeUInt32BE(body.length);
  return Buffer.concat([header, body]);
}
```

### 2.2. Крок 1 — ініціювання клієнтом

Клієнт генерує 32 випадкові байти і надсилає `client_hello` з версією та списком шифрів.

```js
const clientRandom = K.random(32);
const hello = { type: 'client_hello', version: VERSION,
  client_random: clientRandom.toString('hex'), cipher_suites: CIPHER_SUITES };
transcript.push(transport.send(hello));
```

```
CLIENT ━━ КРОК 1/7 ━━ → client_hello
          version        BPZ-TLS/1.0
          client_random  d00909afeec95428…6af8036aac86d684 (32 Б)
          cipher_suites  BPZ_RSA_OAEP_SHA256_WITH_AES_256_GCM_HKDF_SHA256
```

### 2.3. Крок 2 — відповідь сервера

Сервер при старті генерує пару ключів RSA-2048, перевіряє версію, обирає спільний шифр і надсилає `server_hello`
зі своїм random і публічним ключем (PEM). Додатково (бонус) сервер може надіслати самопідписаний сертифікат X.509,
згенерований `scripts/gen-cert.sh`.

```js
const kp = crypto.generateKeyPairSync('rsa', { modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' }, privateKeyEncoding: { type: 'pkcs8', format: 'pem' } });
const serverRandom = K.random(32);
const sh = { type: 'server_hello', server_random: serverRandom.toString('hex'),
  cipher_suite: suite, public_key: publicKey, ...(certificate ? { certificate } : {}) };
```

```
SERVER    згенеровано пару ключів RSA-2048 за 40 мс (базовий варіант, сертифіката немає)
SERVER#1 ━━ КРОК 2/7 ━━ → server_hello
          server_random  38d63853f599db21…a60343c5a8ab8af7 (32 Б)
          public_key     RSA 2048 біт, SHA-256(SPKI) FF:63:3D:47:1C:B8:C0:E9…
```

### 2.4. Крок 3 — автентифікація

У базовому варіанті перевірка сертифіката в центрі сертифікації пропускається, що фіксується в лозі обох сторін.
Якщо сервер надіслав сертифікат, клієнт виводить його subject, issuer, строк дії, відбиток SHA-256 і перевіряє,
що публічний ключ у `server_hello` збігається з ключем у сертифікаті.

```js
if (!K.sameKey(cert.publicKey, serverKey))
  throw new ProtocolError('certificate_key_mismatch', 'public_key із server_hello НЕ збігається з ключем у сертифікаті');
log.step(3, 'пропущено (базовий варіант): перевірка сертифіката в центрі сертифікації не виконується');
```

```
CLIENT    сертифікат сервера (X.509)
          subject         C=UA, ST=Kyiv, L=Kyiv, O=KPI, OU=IM-31 Holoshumov, CN=localhost
          fingerprint256  17:C2:CE:BE:59:27:A3:A0:…
          самопідписаний  так, підпис коректний
CLIENT    ✔ ключ із сертифіката збігається з public_key сервера
CLIENT ━━ КРОК 3/7 ━━ пропущено (базовий варіант)
```

### 2.5. Крок 4 — обмін premaster

Клієнт генерує 48 випадкових байтів і шифрує їх RSA-OAEP (SHA-256) публічним ключем сервера; сервер розшифровує
приватним ключем.

```js
const OAEP = { padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' };
const rsaEncrypt = (pub, data) => crypto.publicEncrypt({ key: pub, ...OAEP }, data);
const rsaDecrypt = (priv, data) => crypto.privateDecrypt({ key: priv, ...OAEP }, data);
```

```
CLIENT ━━ КРОК 4/7 ━━ → premaster (RSA-OAEP, SHA-256)
          premaster            87d97627a306dcde…131a4ac5254c3624 (48 Б)
          encrypted_premaster  12fe05fa10495ae1…6bf63ede03d803a1 (256 Б)
SERVER#1 ━━ КРОК 4/7 ━━ ← premaster розшифровано приватним ключем
          premaster            87d97627a306dcde…131a4ac5254c3624 (48 Б)
```

### 2.6. Крок 5 — генерація ключів сеансу

Обидві сторони незалежно обчислюють master secret і окремі ключі та IV для кожного напрямку.

```js
function deriveKeys(premaster, clientRandom, serverRandom) {
  const salt = Buffer.concat([clientRandom, serverRandom]);
  const master = hkdf(premaster, salt, 'bpz master', 48);
  const expand = (info, len) => hkdf(master, salt, info, len);
  return { master,
    client_write_key: expand('bpz client write key', 32), server_write_key: expand('bpz server write key', 32),
    client_iv: expand('bpz client iv', 12), server_iv: expand('bpz server iv', 12) };
}
```

```
CLIENT ━━ КРОК 5/7 ━━ ключі сеансу (HKDF-SHA256)        SERVER#1 ━━ КРОК 5/7 ━━
  master            aa521ccae5bc4797…bc7ea1f89fe0943f      master            aa521ccae5bc4797…bc7ea1f89fe0943f
  client_write_key  f99f23e4f96bc6de…ebbbe8f9bd78c717      client_write_key  f99f23e4f96bc6de…ebbbe8f9bd78c717
  server_write_key  0ffa5b63668976da…0addd5371c7d2a11      server_write_key  0ffa5b63668976da…0addd5371c7d2a11
  client_iv         1b1d9bf122f03286c8d47260               client_iv         1b1d9bf122f03286c8d47260
```

Збіг ключів на обох сторонах автоматично перевіряє `scripts/demo.sh` (`evidence/demo-summary.txt`) і тест
«повне рукостискання: обидві сторони отримують однакові ключі сеансу».

### 2.7. Крок 6 — готовність клієнта і сервера

Кожна сторона надсилає `finished` з повідомленням «готовий» і `verify_data = HMAC-SHA256(master, label ‖ SHA-256(transcript))`,
зашифроване AES-256-GCM сеансовим ключем. Transcript — усі повідомлення рукостискання в тому вигляді, як їх було
надіслано/отримано. Сервер спочатку перевіряє finished клієнта, потім надсилає свій (його transcript містить і finished клієнта).

```js
const thash = K.transcriptHash(transcript);
const vd = K.verifyData(keys.master, 'client finished', thash);
transport.send(channel.seal('finished', { message: 'готовий', label: 'client finished', verify_data: vd.toString('hex') }));
// на іншій стороні:
if (!K.safeEqualHex(p.verify_data, expected)) throw new ProtocolError('bad_finished', '…');
```

```
CLIENT ━━ КРОК 6/7 ━━ → finished «готовий» (зашифровано AES-256-GCM)
          transcript_hash  11d65b6b2d915306…96396f3604d86c39 (32 Б)
          verify_data      91936a5f4dcd142e…85dc63b60a47f890 (32 Б)
CLIENT ━━ КРОК 6/7 ━━ ← finished сервера «готовий» перевірено
```

### 2.8. Крок 7 — завершення рукостискання і захищений канал

Після взаємної перевірки finished рукостискання завершене, усі дані передаються через `SecureChannel`:
AES-256-GCM, nonce = IV ⊕ номер послідовності, AAD = `тип|seq`, отримувач приймає лише очікуваний seq.

```js
seal(type, payload) {
  const seq = this.sendSeq++;
  const aad = Buffer.from(`${type}|${seq}`);
  const { ct, tag } = aesGcmEncrypt(this.sendKey, nonceFor(this.sendIv, seq), Buffer.from(JSON.stringify(payload)), aad);
  return { type, seq, ct: ct.toString('base64'), tag: tag.toString('hex') };
}
open(msg) {
  if (msg.seq !== this.recvSeq) throw new ProtocolError('bad_seq', '… повтор (replay) …');
  /* AES-GCM decrypt з тим самим nonce і AAD; помилка тегу → bad_record_mac */
}
```

```
CLIENT ━━ КРОК 7/7 ━━ рукостискання завершено — далі тільки AES-256-GCM на ключах сеансу
```

### 2.9. Передача повідомлень чату і текстового файлу

Клієнт (`node client.js`) надсилає кожен рядок як зашифроване повідомлення, сервер підтверджує отримання; рядок,
набраний у консолі сервера, надсилається всім клієнтам. Команда `/send <шлях>` передає файл: клієнт обчислює
SHA-256, сервер після розшифрування обчислює SHA-256 повторно, зберігає файл у `received/` і повертає хеш.
Сервер обслуговує кількох клієнтів одночасно, кожен — зі своїм сеансом і ключами (`evidence/demo-multi-*.log`).

```
CLIENT    💬 я: Привіт, сервере! Це захищений чат ІМ-31.
CLIENT    → data seq=1 (AES-256-GCM: шифротекст 94 Б, tag bf4cd4d1…)
CLIENT    📄 надсилаю файл «message.txt»   sha256 430a2cd94ebd0a52…8e70feed80732660c
SERVER#1  ✔ 📄 файл «message.txt» отримано й збережено
          sha256 заявлений   430a2cd94ebd0a520ea6b439c58bc29cdf67c16021bab038e70feed80732660c
          sha256 обчислений  430a2cd94ebd0a520ea6b439c58bc29cdf67c16021bab038e70feed80732660c
          saved_as           received/1794740510921-message.txt
CLIENT    ✔ сервер зберіг файл «message.txt»
```

## 3. Тестування

Автоматичні тести (`npm test`, вбудований `node:test`) — 13 із 13 пройдено (`evidence/npm-test.txt`).
Негативні сценарії через TCP і проксі `mitm.js` — `npm run negative` (`evidence/neg*.log`, `evidence/negative-summary.txt`).

| № | Сценарій | Очікуваний результат | Фактичний результат |
|---|---|---|---|
| 1 | Повне рукостискання (базовий варіант) | кроки 1–7, однакові ключі | ✔ однакові master, client/server_write_key, IV |
| 2 | Рукостискання з X.509 (бонус) | сертифікат розібрано, ключ збігається | ✔ |
| 3 | Чат в обидва боки | повідомлення розшифровані, підтверджені | ✔ |
| 4 | Передача файлу | SHA-256 однаковий, файл у `received/` | ✔ `430a2cd9…0732660c` на обох сторонах |
| 5 | Два клієнти одночасно | окремі сеанси, різні ключі | ✔ різні master |
| 6 | MITM підміняє публічний ключ | finished не сходиться, розрив | ✔ сервер: «finished клієнта не збігається з transcript hash», клієнт: alert |
| 7 | MITM підміняє ключ при наявному сертифікаті | відхилено на кроці 2 | ✔ «public_key … НЕ збігається з ключем у сертифікаті» |
| 8 | Змінено 1 байт шифротексту | AES-GCM відхиляє | ✔ «Unsupported state or unable to authenticate data» |
| 9 | Повтор повідомлення (replay) | відхилено за seq | ✔ «seq=1, очікувався seq=2 — повтор (replay)» |
| 10 | Невірний finished | рукостискання не завершене | ✔ сервер: bad_finished, крок 7 відсутній |
| 11 | Немає спільного шифру (downgrade) | alert handshake_failure | ✔ (тест) |
| 12 | Підміна поля seq | AES-GCM відхиляє | ✔ (тест) |

Примітка до сценарію 6: проксі розшифрував premaster своїм ключем і перешифрував справжнім ключем сервера, тому ключі
сеансу в обох сторін однакові, але transcript відрізняється (у клієнта — ключ MITM). Це показує роль Finished.
Посередник, який веде два незалежні рукостискання, міг би обчислити Finished сам — від нього захищає лише крок 3
(перевірка сертифіката в CA), що належить до розширеного варіанту.

## 4. Висновки

Реалізовано імітацію рукостискання TLS/SSL з усіма сімома кроками умови: обмін випадковими числами, передача публічного
ключа RSA-2048 (і, додатково, самопідписаного сертифіката X.509), передача premaster через RSA-OAEP, виведення ключів
сеансу HKDF-SHA256, взаємна перевірка Finished на основі transcript hash і захищений канал AES-256-GCM з унікальним nonce
і захистом від повтору. Через захищений канал працюють чат і передача текстового файлу з контролем SHA-256.
Негативні сценарії підтверджують, що підміна ключа, зміна шифротексту, повтор повідомлень і невірний Finished
виявляються і призводять до розриву з'єднання. Обмеження базового варіанту — відсутність автентифікації сервера через
CA і прямої секретності (обмін RSA); їх усувають перевірка ланцюжка сертифікатів і ефемерний обмін (EC)DHE, як у TLS 1.3.

## 5. Список літератури

1. Dierks T., Rescorla E. RFC 5246. The Transport Layer Security (TLS) Protocol Version 1.2. — IETF, 2008.
2. Rescorla E. RFC 8446. The Transport Layer Security (TLS) Protocol Version 1.3. — IETF, 2018.
3. Krawczyk H., Eronen P. RFC 5869. HMAC-based Extract-and-Expand Key Derivation Function (HKDF). — IETF, 2010.
4. Moriarty K. et al. RFC 8017. PKCS #1: RSA Cryptography Specifications Version 2.2. — IETF, 2016.
5. Dworkin M. NIST SP 800-38D. Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC. — NIST, 2007.
6. Cooper D. et al. RFC 5280. Internet X.509 Public Key Infrastructure Certificate and CRL Profile. — IETF, 2008.
7. Node.js Documentation: Crypto. — https://nodejs.org/api/crypto.html
8. Node.js Documentation: Net. — https://nodejs.org/api/net.html
9. Власний репозиторій з кодом РГР: https://github.com/holoshumov/bpz-labs/tree/main/rgr
