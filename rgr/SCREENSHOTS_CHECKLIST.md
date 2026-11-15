# РГР — скріншоти, які треба зняти самому

Підготовка: `cd ~/labs/bpz/rgr`, два (для MITM — три) вікна Terminal поруч, шрифт крупніше (Cmd +).
Кольорові кроки видно лише в справжньому терміналі (у файлах `evidence/` — без кольорів).

| № | Що запустити | Що має бути на скріншоті |
|---|---|---|
| 1 | `npm test` | 13 зелених ✔, внизу `pass 13`, `fail 0` |
| 2 | Т1: `node server.js --no-cert`, Т2: `node client.js` | Обидва вікна поруч: КРОКИ 1–7 у клієнта й сервера; видно, що `master`, `client_write_key`, `server_write_key` однакові в обох вікнах; крок 3 «пропущено (базовий варіант)» |
| 3 | те саме з `--verbose` на обох | повні значення `client_random`, `server_random`, `premaster`, ключів (для звіту: розділ «Генерація ключів сеансу») |
| 4 | у клієнті набрати 2–3 повідомлення, у сервері — відповідь | чат в обидва боки: `→ data seq=…` / `← data … розшифровано`, `💬` |
| 5 | у клієнті `/send samples/message.txt` | клієнт: sha256 до відправлення; сервер: «файл отримано й збережено», sha256 заявлений = обчислений, шлях `received/…`; клієнт: «сервер зберіг файл», той самий sha256 |
| 6 | `ls received/ && cat received/*message.txt` | файл з'явився і читається |
| 7 | два клієнти до одного сервера | у сервера `SERVER#1` і `SERVER#2`, різні `master` |
| 8 | (бонус) `npm run cert`, потім `node server.js` (без `--no-cert`) і `node client.js` | у клієнта блок «сертифікат сервера (X.509)»: subject, issuer, строк, fingerprint256, «ключ із сертифіката збігається» |
| 9 | MITM: Т1 `node server.js --no-cert`, Т2 `node mitm.js --mode keyswap`, Т3 `node client.js --port 9443` | MITM «ключ ПІДМІНЕНО», «premaster розшифровано»; сервер ✘ «finished клієнта не збігається…»; клієнт ✘ alert |
| 10 | MITM із сертифікатом: `node server.js`, `node mitm.js --mode keyswap-cert`, клієнт на 9443 | клієнт ✘ на кроці 2: «public_key … НЕ збігається з ключем у сертифікаті» |
| 11 | `node mitm.js --mode tamper` + клієнт на 9443, надіслати повідомлення | MITM «змінено 1 байт»; сервер ✘ «AES-GCM … unable to authenticate data» |
| 12 | `node mitm.js --mode replay` + клієнт на 9443, надіслати повідомлення | MITM «надіслано ПОВТОРНО»; сервер ✘ «seq=1, очікувався seq=2 — повтор (replay)» |
| 13 | `node server.js --no-cert` + `node client.js --bad-finished` | клієнт ⚠ «verify_data навмисно зіпсовано»; сервер ✘ «finished … не збігається»; КРОКУ 7 немає |
| 14 | `npm run negative` (або `cat evidence/negative-summary.txt`) | зведення всіх 5 негативних сценаріїв, код виходу клієнта 1 |
| 15 | GitHub: https://github.com/holoshumov/bpz-labs/tree/main/rgr | структура папки `rgr/` у браузері (для списку літератури) |

Між сценаріями зупиняйте процеси Ctrl+C. Якщо порт зайнятий: `lsof -i :8443`.
