const express = require('express');
const bcrypt = require('bcrypt');
const session = require('express-session');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const app = express();
require('dotenv').config();

app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: true
}));


// Database
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


// Routes
app.get('/signup', (req, res) => res.render('signup'));
app.get('/login', (req, res) => res.render('login'));

// Signup Logic
app.post('/signup', async (req, res) => {
    try {
        // Prevent short passwords
        if (req.body.password.length <~ 8){
            return res.status(400).send("Password is too short to use.");
        }

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
                req.session.username = user.username;
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

app.get('{/*path}', (req, res) => {
    if (!req.session.userId) return res.redirect('/login');
    res.redirect('/dashboard');
});

app.listen(3000, () => console.log('Server running on http://localhost:3000'));