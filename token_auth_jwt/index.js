// token_auth, переписаний на JWT (ЛР1, додаткове завдання).
// Замість випадкового session id + sessions.json сервер видає підписаний JWT.
// Сервер нічого не зберігає (stateless): усе потрібне лежить у самому токені,
// а справжність перевіряється підписом HMAC-SHA256.
const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const jwt = require('./jwt');

const port = 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'change-me-lab1-secret';
const JWT_TTL_SEC = 60 * 60; // 1 година

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Middleware: дістаємо токен з заголовка Authorization (Bearer <jwt>) і перевіряємо його
app.use((req, res, next) => {
    const header = req.get('Authorization');
    if (!header) return next();

    const token = header.startsWith('Bearer ') ? header.slice(7) : header;
    try {
        req.user = jwt.verify(token, JWT_SECRET);
        console.log('JWT OK, payload:', req.user);
    } catch (e) {
        console.log('JWT rejected:', e.message);
        return res.status(401).json({ error: e.message });
    }
    next();
});

app.get('/', (req, res) => {
    if (req.user) {
        return res.json({
            username: req.user.username,
            exp: new Date(req.user.exp * 1000).toISOString(),
            logout: 'http://localhost:3000/logout'
        });
    }
    res.sendFile(path.join(__dirname, 'index.html'));
});

// JWT stateless: "вийти" = клієнт видаляє токен (див. index.html)
app.get('/logout', (req, res) => {
    res.redirect('/');
});

const users = [
    { login: 'Login', password: 'Password', username: 'Username' },
    { login: 'Login1', password: 'Password1', username: 'Username1' }
];

app.post('/api/login', (req, res) => {
    const { login, password } = req.body;
    const user = users.find((u) => u.login == login && u.password == password);

    if (!user) {
        return res.status(401).send();
    }

    const token = jwt.sign({ sub: user.login, username: user.username }, JWT_SECRET, JWT_TTL_SEC);
    console.log('Issued JWT:', token);
    res.json({ token });
});

app.listen(port, () => {
    console.log(`JWT token_auth app listening on port ${port}`);
});
