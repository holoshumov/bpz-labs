# ЛР1 — чек-лист скріншотів (робити самому)

Загальне:
- Сервери всі на порту 3000 → запускати **по одному**. Термінал 1: `npm run <app>`, термінал 2: `./requests.sh <app>`. Зупинка сервера — `Ctrl+C`.
- Браузер: Chrome, краще **вікно інкогніто** (немає старих cookie / кешованого Basic-логіну). DevTools: `Cmd+Option+I` → вкладка **Network**, увімкнути **Preserve log**.
- Сторінки forms/token/jwt тягнуть axios з unpkg.com — потрібен інтернет.
- На кожному скріншоті бажано, щоб було видно адресний рядок (`localhost:3000`) і годинник/дату системи.
- Назви файлів: `01_basic_browser.png`, `02_basic_network.png` … (нумерація як нижче).

---

## 1. basic_auth (`npm run basic`)
| № | Що зробити | Що має бути видно |
|---|---|---|
| 01 | Відкрити `http://localhost:3000` | Нативне вікно браузера «Sign in» (бо сервер відповів `401` + `WWW-Authenticate: Basic realm="Ukraine"`). Ввести `DateArt` / `2408` — скрін **до** натискання «Sign in» (видно логін і поле пароля). |
| 02 | Натиснути Sign in | Сторінка з текстом `Hello DateArt`. |
| 03 | DevTools → Network → запит `localhost` → Headers | **Request Headers**: `Authorization: Basic RGF0ZUFydDoyNDA4`; Status `200 OK`. (Якщо запиту нема — перезавантажити сторінку `Cmd+R` з відкритим DevTools.) |
| 04 | (бонус) у тому ж Network знайти перший запит або відкрити в новому інкогніто | `401 Unauthorized` + Response Header `WWW-Authenticate: Basic realm="Ukraine"`. |
| 05 | Термінал 1 (лог сервера) | Рядки `authorizationHeader Basic RGF0...`, `decodedAuthorizationHeader DateArt:2408` — видно, що сервер (і будь-хто в мережі) розкодовує пароль з base64. |
| 06 | Термінал 2: `./requests.sh basic` | Три блоки: `401` (без заголовка), `401` (невірний пароль), `200 Hello DateArt`. |

## 2. forms_auth (`npm run forms`)
| № | Що зробити | Що має бути видно |
|---|---|---|
| 07 | Відкрити `http://localhost:3000`, DevTools → Network → запит `localhost` → Headers | Форма Login; Response Header `Set-Cookie: session=<uuid>; HttpOnly`. |
| 08 | Ввести `Login` / `Password`, натиснути Login | Alert «You have successfully logged in, Login». Скрін з alert. |
| 09 | Network → запит `login` (POST `/api/login`) | Request Headers: `Cookie: session=<uuid>`; Payload: `{"login":"Login","password":"Password"}`; Status `200`; Response `{"username":"Login"}`. |
| 10 | Після reload: Network → запит `localhost` (GET /) | Response: `{"username":"Username","logout":"http://localhost:3000/logout"}` — сервер впізнав сесію по cookie. |
| 11 | DevTools → **Application** → Storage → Cookies → `http://localhost:3000` | Cookie `session`, значення uuid, прапорець **HttpOnly ✓**. |
| 12 | Відкрити файл `forms_auth/sessions.json` (VS Code або `cat forms_auth/sessions.json`) | Той самий uuid як ключ і `{"username":"Username","login":"Login"}` — стан зберігає **сервер**. |
| 13 | (бонус) Невірний пароль у формі | Червоне «Invalid username and/or password», у Network `login` → `401`. |
| 14 | Термінал 2: `./requests.sh forms` | `Set-Cookie: session=...`, потім `200 {"username":"Login"}`, `200 {"username":"Username",...}`, `401`. |

## 3. token_auth (`npm run token`)
| № | Що зробити | Що має бути видно |
|---|---|---|
| 15 | Відкрити `http://localhost:3000`, ввести `Login` / `Password` → Login | Сторінка «Hello Username» і посилання Logout. |
| 16 | Network → POST `login` → Response | `{"token":"<uuid>"}` — токен = випадковий id сесії. |
| 17 | Network → XHR GET `localhost` (тип `xhr`, ініціатор axios) → Headers | Request Header `Authorization: <uuid>` (без префікса Bearer); Response `{"username":"Username",...}`. |
| 18 | Application → **Session Storage** → `http://localhost:3000` | Ключ `session` = `{"token":"<uuid>"}` — токен тримає клієнт у sessionStorage, cookie не використовується. |
| 19 | `cat token_auth/sessions.json` | uuid → `{"username":"Username","login":"Login"}` + купа порожніх `{}` (сервер створює запис на кожен запит без токена). |
| 20 | Термінал 2: `./requests.sh token` | `{"token":"..."}`, потім `HTTP/1.1 200 OK` і `{"username":"Username",...}`. |

## 4. token_auth_jwt (`npm run jwt`) — додаткове завдання
| № | Що зробити | Що має бути видно |
|---|---|---|
| 21 | Відкрити `http://localhost:3000`, логін `Login` / `Password` | «Hello Username», під ним `JWT: eyJ...` і розкодований Payload (`sub`, `username`, `iat`, `exp`). |
| 22 | Network → POST `login` → Response | `{"token":"eyJhbGciOiJIUzI1NiIs..."}` — три частини через крапку. |
| 23 | Network → XHR GET `localhost` → Headers | Request Header `Authorization: Bearer eyJ...`; Response `{"username":"Username","exp":"...","logout":...}`. |
| 24 | Application → Session Storage | `session` = `{"token":"eyJ..."}`. |
| 25 | Скопіювати токен → https://jwt.io (Debugger) | Header `{"alg":"HS256","typ":"JWT"}`, Payload з `sub/username/iat/exp`. Ввести секрет `change-me-lab1-secret` у поле «secret» → **Signature Verified**. (Токен навчальний, секрет тестовий — вставляти на jwt.io можна; справжні токени — ні.) |
| 26 | Термінал 1 (лог сервера) | `Issued JWT: ...`, `JWT OK, payload: {...}`, `JWT rejected: Invalid signature`. |
| 27 | Термінал 2: `./requests.sh jwt` | Розкодовані header/payload, `200` з валідним токеном, `401 {"error":"Invalid signature"}` для підробленого payload (`username: admin`). |
| 28 | Зміна секрету: зупинити сервер, `JWT_SECRET=інший npm run jwt`, оновити сторінку в браузері (старий токен у sessionStorage) | Network → GET `/` → `401 {"error":"Invalid signature"}`; сторінка залишається на формі логіну. Повторний логін → працює. (Готовий вивід: `evidence/jwt_secret_rotation.txt`.) |

---
Мінімум для повного балу: 01–03, 07, 09, 11, 15–18, 21–23, 25, 27–28 + термінальні скріни 06, 14, 20.
