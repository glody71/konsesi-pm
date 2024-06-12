// server/index.js

require('dotenv').config();
const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const port = process.env.PORT || 5000;

// Middleware
app.use(express.json());
app.use(cors());

// MySQL Connection
const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
});

db.connect((err) => {
    if (err) {
        console.error('Error connecting to MySQL:', err.message);
        return;
    }
    console.log('Connected to MySQL');
});

// Root route
app.get('/', (req, res) => {
    res.send('Hello, World! Welcome to the Vite React Authentication API');
});

// Other routes...
app.post('/register', (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = bcrypt.hashSync(password, 8);

    db.query('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword], (err, results) => {
        if (err) {
            console.error('Error during registration:', err.message);
            return res.status(500).send('Server error');
        }
        res.status(201).send('User registered');
    });
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;

    db.query('SELECT * FROM users WHERE username = ?', [username], (err, results) => {
        if (err) {
            console.error('Error during login:', err.message);
            return res.status(500).send('Server error');
        }
        if (results.length === 0) return res.status(404).send('User not found');

        const user = results[0];
        const passwordIsValid = bcrypt.compareSync(password, user.password);
        if (!passwordIsValid) return res.status(401).send('Invalid password');

        const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.status(200).send({ auth: true, token });
    });
});

app.get('/me', (req, res) => {
    const token = req.headers['x-access-token'];
    if (!token) return res.status(403).send('No token provided');

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) return res.status(500).send('Failed to authenticate token');

        db.query('SELECT * FROM users WHERE id = ?', [decoded.id], (err, results) => {
            if (err) {
                console.error('Error fetching user data:', err.message);
                return res.status(500).send('Server error');
            }
            if (results.length === 0) return res.status(404).send('User not found');
            res.status(200).send(results[0]);
        });
    });
});

app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
