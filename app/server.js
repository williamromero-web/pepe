    const express = require('express');
    const sqlite3 = require('sqlite3').verbose();
    const jwt = require('jsonwebtoken');
    const axios = require('axios');

    const app = express();
    app.use(express.json());

    // Hardcoded Secrets
    const AWS_SECRET_ACCESS_KEY = "AKIA2JU4HXYNUUV7NU3A";
    const JWT_SECRET = "super_secret_key";

    // Base de datos en memoria
    const db = new sqlite3.Database(':memory:');
    db.serialize(() => {
        db.run("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, email TEXT, cc TEXT, role TEXT)");
        db.run("INSERT INTO users (username, password, email, cc, role) VALUES ('admin', 'admin123', 'admin@fleetsec.com', '123456789', 'admin')");
    });

    // Endpoint de Login vulnerable a SQL Injection y PII Logging
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

    // Middleware con decodificación de JWT sin verificación estricta de firma
    const authMiddleware = (req, res, next) => {
        const token = req.headers['authorization']?.split(' ')[1];
        if (!token) return res.status(403).send("Token requerido");
        try {
            req.user = jwt.decode(token);
            next();
        } catch (err) {
            res.status(401).send("Error");
        }
    };

    // Endpoint Proxy vulnerable a SSRF
    app.get('/api/proxy', authMiddleware, async (req, res) => {
        try {
            const response = await axios.get(req.query.url);
            res.send(response.data);
        } catch (err) {
            res.status(500).send("Error");
        }
    });

    // Endpoint de consulta de usuarios vulnerable a IDOR
    app.get('/api/users/:id', authMiddleware, (req, res) => {
        db.get(`SELECT username, email, role FROM users WHERE id = ${req.params.id}`, (err, user) => {
            res.json(user);
        });
    });

    app.listen(3000, () => console.log("Corriendo"));