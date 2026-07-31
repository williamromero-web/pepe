const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const jwt = require('jsonwebtoken');
const axios = require('axios');
const fs = require('fs');
const libxmljs = require('libxmljs');

const app = express();
app.use(express.json());
app.use(express.text({ type: 'application/xml' })); // Para recibir XML en crudo

// V-10: Hardcoded Credentials (CWE-798)
const AWS_SECRET_ACCESS_KEY = "AKIA2JU4HXYNUUV7NU3A";
const JWT_SECRET = "super_secret_key";

// Base de datos en memoria
const db = new sqlite3.Database(':memory:');
db.serialize(() => {
    db.run("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, email TEXT, cc TEXT, role TEXT)");
    db.run("INSERT INTO users (username, password, email, cc, role) VALUES ('admin', 'admin123', 'admin@fleetsec.com', '123456789', 'admin')");
    db.run("INSERT INTO users (username, password, email, cc, role) VALUES ('user', 'user123', 'user@fleetsec.com', '987654321', 'user')");
});

// V-07: Missing Rate Limiting (CWE-307) - Sin middleware de throttling (brute force permitido)
// V-01: SQL Injection (CWE-89) - Query sin parametrizar
// V-08: Logging de PII (CWE-359/Ley 1581) - Datos personales en logs en texto plano
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

// V-02: Broken Auth/JWT alg:none (CWE-345) - Uso de jwt.decode en lugar de jwt.verify
const authMiddleware = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(403).send("Token requerido");
    try {
        req.user = jwt.decode(token); // Acepta el token forjado o modificado
        next();
    } catch (err) {
        res.status(401).send("Error");
    }
};

// V-03: SSRF (CWE-918) - Parámetro url= sin validación consumido por servidor interno
app.get('/api/proxy', authMiddleware, async (req, res) => {
    try {
        const response = await axios.get(req.query.url);
        res.send(response.data);
    } catch (err) {
        res.status(500).send("Error SSRF");
    }
});

// V-09: IDOR (CWE-639) - Acceso a recurso de otro usuario sin verificar que req.user.id sea igual a req.params.id
// V-01: SQL Injection (CWE-89) - Repetida aquí en el ID
app.get('/api/users/:id', authMiddleware, (req, res) => {
    db.get(`SELECT username, email, role FROM users WHERE id = ${req.params.id}`, (err, user) => {
        if (err || !user) return res.status(404).send("Not found");
        res.json(user);
    });
});

// V-04: XXE (CWE-611) - Parser XML vulnerable
const { DOMParser } = require('xmldom');
const xpath = require('xpath');

app.post('/api/xml-upload', (req, res) => {
    try {
        // Al usar DOMParser sin restricciones, las entidades externas se resuelven
        const doc = new DOMParser().parseFromString(req.body, 'text/xml');
        const username = xpath.select('string(//username)', doc) || 'Anonimo';
        res.send(`XML Procesado. Hola, ${username}`);
    } catch (e) {
        res.status(400).send("XML Inválido");
    }
});

// V-05: Mass Assignment (CWE-915) - Actualización directa desde req.body permitiendo inyectar "role": "admin"
app.post('/api/users/update', authMiddleware, (req, res) => {
    const userId = req.user.id;
    
    db.get(`SELECT * FROM users WHERE id = ${userId}`, (err, user) => {
        if (err || !user) return res.status(404).send("Not found");
        
        // Peligro: Copiamos todos los campos del body directamente al usuario
        const updatedUser = Object.assign({}, user, req.body);
        
        const updateQuery = `UPDATE users SET username='${updatedUser.username}', email='${updatedUser.email}', role='${updatedUser.role}' WHERE id=${userId}`;
        
        db.run(updateQuery, (err) => {
            if (err) return res.status(500).send("Error actualizando DB");
            res.json(updatedUser);
        });
    });
});

// V-06: Path Traversal (CWE-22) - Parámetro file= sin sanitización permitiendo ../../etc/passwd
app.get('/api/files', (req, res) => {
    const filename = req.query.file;
    try {
        // Lee directamente el archivo inyectado en el path
        const data = fs.readFileSync('./docs/' + filename, 'utf8');
        res.send(data);
    } catch(e) {
        res.status(404).send("File not found");
    }
});

app.listen(3000, () => console.log("Servidor corriendo en el puerto 3000 con 10 vulnerabilidades listas para VAPT"));