const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const jwt = require('jsonwebtoken');
const axios = require('axios');
const fs = require('fs');
const { DOMParser } = require('xmldom');
const xpath = require('xpath');

const app = express();
app.use(express.json());
app.use(express.text({ type: 'application/xml' })); 

// V-10: Hardcoded Credentials (CWE-798)
const AWS_SECRET_ACCESS_KEY = "AKIA2JU4HXYNUUV7NU3A";
const JWT_SECRET = "super_secret_key";

const db = new sqlite3.Database(':memory:');
db.serialize(() => {
    db.run("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, email TEXT, cc TEXT, role TEXT)");
    db.run("INSERT INTO users (username, password, email, cc, role) VALUES ('admin', 'admin123', 'admin@fleetsec.com', '123456789', 'admin')");
    db.run("INSERT INTO users (username, password, email, cc, role) VALUES ('user', 'user123', 'user@fleetsec.com', '987654321', 'user')");
});

// V-07: Missing Rate Limiting / V-01: SQL Injection / V-08: Logging de PII
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
    db.get(query, (err, user) => {
        if (err || !user) return res.status(401).send("Error");
        console.log(`[INFO] Login - Usuario: ${user.username}, Email: ${user.email}, Cédula: ${user.cc}`);
        const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET);
        res.json({ token });
    });
});

const authMiddleware = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(403).send("Token requerido");
    try {
        req.user = jwt.decode(token); // V-02: Broken Auth
        next();
    } catch (err) {
        res.status(401).send("Error");
    }
};

// V-03: SSRF
app.get('/api/proxy', authMiddleware, async (req, res) => {
    try {
        const response = await axios.get(req.query.url);
        res.send(response.data);
    } catch (err) {
        res.status(500).send("Error SSRF");
    }
});

// V-09: IDOR y V-01: SQLi
app.get('/api/users/:id', authMiddleware, (req, res) => {
    db.get(`SELECT username, email, role FROM users WHERE id = ${req.params.id}`, (err, user) => {
        if (err || !user) return res.status(404).send("Not found");
        res.json(user);
    });
});

// V-04: XXE
app.post('/api/xml-upload', (req, res) => {
    try {
        const doc = new DOMParser().parseFromString(req.body, 'text/xml');
        const username = xpath.select('string(//username)', doc) || 'Anonimo';
        res.send(`XML Procesado. Hola, ${username}`);
    } catch (e) {
        res.status(400).send("XML Inválido");
    }
});

// V-05: Mass Assignment
app.post('/api/users/update', authMiddleware, (req, res) => {
    const userId = req.user.id;
    db.get(`SELECT * FROM users WHERE id = ${userId}`, (err, user) => {
        if (err || !user) return res.status(404).send("Not found");
        const updatedUser = Object.assign({}, user, req.body);
        const updateQuery = `UPDATE users SET username='${updatedUser.username}', email='${updatedUser.email}', role='${updatedUser.role}' WHERE id=${userId}`;
        db.run(updateQuery, (err) => {
            if (err) return res.status(500).send("Error actualizando DB");
            res.json(updatedUser);
        });
    });
});

// V-06: Path Traversal
app.get('/api/files', (req, res) => {
    const filename = req.query.file;
    try {
        const data = fs.readFileSync('./docs/' + filename, 'utf8');
        res.send(data);
    } catch(e) {
        res.status(404).send("File not found");
    }
});

// Expuesto a 0.0.0.0 para ZAP
app.listen(3000, '0.0.0.0', () => console.log("Servidor escuchando en 0.0.0.0:3000"));