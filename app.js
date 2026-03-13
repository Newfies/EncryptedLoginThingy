require('dotenv').config();
const express = require('express');
const bcrypt = require('bcrypt');
const session = require('express-session');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const fs = require('fs');
const app = express();

const PORT = process.env.PORT || 3000;

app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
    secret: process.env.SECRET || 'fallback-secret',
    resave: false,
    saveUninitialized: true
}));

// GLOBAL DB VARIABLE
let db;

// FUNCTION TO INITIALIZE/RE-OPEN DATABASE & CREATE AUTO-ACCOUNT
async function getDbConnection() {
    db = new sqlite3.Database('./database.sqlite', async (err) => {
        if (err) return console.error('Database opening error:', err);
        
        // 1. Create the table
        db.run(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
        )`, async () => {
            
            // 2. Create the automatic "server" account
            try {
                const adminPass = process.env.PASSWORD;
                const hashedAdminPass = await bcrypt.hash(adminPass, 12);
                
                const sql = `INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)`;
                db.run(sql, ['server', hashedAdminPass], (err) => {
                    if (!err) console.log('Database initialized. Admin "server" account ready.');
                });
            } catch (e) {
                console.error("Error creating auto-account:", e);
            }
        });
    });
}

// Initial connection
getDbConnection();

// Middleware to ensure DB exists
app.use((req, res, next) => {
    if (!fs.existsSync('./database.sqlite')) {
        getDbConnection();
    }
    next();
});

// Routes
app.get('/signup', (req, res) => res.render('signup'));
app.get('/login', (req, res) => res.render('login'));

app.post('/signup', async (req, res) => {
    try {
        if (req.body.password.length < 8) {
            return res.status(400).send("Password must be 8 or more characters.");
        }
        const hashedPassword = await bcrypt.hash(req.body.password, 12);
        const sql = `INSERT INTO users (username, password) VALUES (?, ?)`;
        db.run(sql, [req.body.username, hashedPassword], (err) => {
            if (err) return res.status(400).send("Username already exists.");
            res.redirect('/login');
        });
    } catch { res.redirect('/signup'); }
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, user) => {
        if (err || !user) return res.send('User not found');
        if (await bcrypt.compare(password, user.password)) {
            req.session.userId = user.id;
            req.session.username = user.username;
            res.redirect('/dashboard');
        } else {
            res.send('Invalid password');
        }
    });
});

// Clear Database Route (Only accessible by user: server)
app.get('/clear', (req, res) => {
    if (req.session.username === 'server') {
        console.log("Authorized clear request from server user.");
        db.close((err) => {
            if (err) return res.status(500).send("Error closing database.");
            fs.unlink('./database.sqlite', (err) => {
                if (err) return res.send("File already deleted.");
                
                // Re-init database and create the "server" user again automatically
                getDbConnection();
                
                res.send("<h1>Database Wiped</h1><p>The database has been reset. The 'server' account has been recreated.</p><a href='/login'>Login again</a>");
            });
        });
    } else {
        res.status(403).send("Access Denied: Only the 'server' user can clear the database.");
    }
});

app.get('/dashboard', (req, res) => {
    if (!req.session.userId) return res.redirect('/login');
    res.render('dashboard', { username: req.session.username });
});

app.post('/logout', (req, res) => {
    req.session.destroy(() => {
        res.clearCookie('connect.sid');
        res.redirect('/login');
    });
});

app.get('/', (req, res) => {
    if (req.session.userId) return res.redirect('/dashboard');
    res.redirect('/login');
});

app.get('{/*path}', (req, res) => {
    if (!req.session.userId) return res.redirect('/login');
    res.redirect('/dashboard');
});

app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));