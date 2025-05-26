// index.js — Secure Auth App Entry Point (Using Route Group for Auth)
const express = require('express');
const cookieParser = require('cookie-parser');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const jwt = require('jsonwebtoken');
const authRoutes = require('./routes/auth'); // Import router

const app = express();
const SECRET = 'super_secret_key';
const db = new sqlite3.Database('./users.db');

// Create users table if not exists
db.run(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL
)`);

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Middleware to verify JWT token
function requireAuth(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ message: 'Unauthorized' });

  jwt.verify(token, SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Forbidden' });
    req.user = user;
    next();
  });
}

// Route group for auth: /auth/register, /auth/login, /auth/logout
app.use('/auth', authRoutes);

// Homepage
app.get('/', (req, res) => {
  const token = req.cookies.token;
  if (!token) return res.render('index', { user: null });

  jwt.verify(token, SECRET, (err, user) => {
    if (err) return res.render('index', { user: null });
    res.render('index', { user });
  });
});

// Example protected route
app.get('/profile', requireAuth, (req, res) => {
  res.json({ message: `Welcome ${req.user.name}! This is your profile.` });
});

// 404 Not Found
app.use((req, res, next) => {
  res.status(404).render('404', { url: req.originalUrl });
});

// 500 Internal Server Error
app.use((err, req, res, next) => {
  console.error('Server Error:', err.stack);
  res.status(500).render('500', { error: err });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));
