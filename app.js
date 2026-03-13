const express = require('express');
const bcrypt = require('bcrypt');
const session = require('express-session');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
require('dotenv').config();

const app = express();

// 2. Setup Database Connection
const db = new sqlite3.Database('./database.sqlite', (err) => {
    if (err) console.error('Database opening error:', err);
    console.log('Connected to SQLite database.');
});

// Create users table if it doesn't exist
db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
)`);

app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: true
}));

// Routes
app.get('/signup', (req, res) => res.render('signup'));
app.get('/login', (req, res) => res.render('login'));

// Signup Logic
app.post('/signup', async (req, res) => {
    try {
        const hashedPassword = await bcrypt.hash(req.body.password, 12);
        const { username } = req.body;

        // Insert user into Database
        const sql = `INSERT INTO users (username, password) VALUES (?, ?)`;
        db.run(sql, [username, hashedPassword], function(err) {
            if (err) {
                console.error(err.message);
                return res.send("Username already exists.");
            }
            res.redirect('/login');
        });
    } catch {
        res.redirect('/signup');
    }
});

// Login Logic
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    // Find user in Database
    const sql = `SELECT * FROM users WHERE username = ?`;
    db.get(sql, [username], async (err, user) => {
        if (err) return res.status(500).send("Server error");
        if (!user) return res.send('User not found');

        try {
            if (await bcrypt.compare(password, user.password)) {
                req.session.userId = user.id;
                req.session.username = user.username; // Save username for dashboard
                res.redirect('/dashboard');
            } else {
                res.send('Invalid password');
            }
        } catch {
            res.status(500).send();
        }
    });
});

app.get('/dashboard', (req, res) => {
    if (!req.session.userId) return res.redirect('/login');
    // Pass the username to the template
    res.render('dashboard', { username: req.session.username });
});

app.post('/logout', (req, res) => {
    req.session.destroy(() => {
        res.clearCookie('connect.sid');
        res.redirect('/login');
    });
});

// Express 5 syntax for "match everything"
app.get('{/*path}', (req, res) => {
    if (!req.session.userId) return res.redirect('/login');
    res.redirect('/dashboard');
});

app.listen(3000, () => console.log('Server running on http://localhost:3000'));