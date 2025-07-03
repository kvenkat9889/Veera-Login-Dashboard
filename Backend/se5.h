require('dotenv').config();

const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const multer = require('multer');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const path = require('path');

const app = express();
const port = process.env.PORT || 3081;
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret_key';

// PostgreSQL connection
const pool = new Pool({
  user: process.env.DB_USER || 'postgres',
  host: process.env.DB_HOST || 'postgres',
  database: process.env.DB_DATABASE || 'login',
  password: process.env.DB_PASSWORD || 'admin834',
  port: parseInt(process.env.DB_PORT) || 5432,
});

// CORS setup
const allowedOrigins = [
  'http://127.0.0.1:5500',
  'http://13.221.233.193:8115',
  'http://13.221.233.193:8116',
  'http://13.221.233.193:8117',
  'http://13.221.233.193:8118'
];

app.use(cors({
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS: ' + origin));
    }
  },
  credentials: true,
  allowedHeaders: ['Content-Type', 'Authorization'],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  exposedHeaders: ['set-cookie']
}));

app.use(express.json());
app.use(cookieParser());

// Serve static files (if any)
app.use(express.static(path.join(__dirname, '../')));

// File uploads (for profile picture)
const storage = multer.memoryStorage();
const upload = multer({ storage });

// Middleware to check JWT
const authenticateToken = (req, res, next) => {
  const token = req.cookies.token ||
                req.headers['authorization']?.split(' ')[1] ||
                req.query.token;

  if (!token) return res.status(401).json({ error: 'No token provided' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      res.clearCookie('token');
      return res.status(403).json({ error: 'Invalid token' });
    }
    req.user = user;
    next();
  });
};

// Validate email format
const validateEmail = (email) => /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(email);

// Database init
const initDatabase = async () => {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name VARCHAR(30) NOT NULL,
        email VARCHAR(100) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        profile_picture TEXT
      );
    `);
    console.log('✅ Database initialized');
  } catch (err) {
    console.error('❌ Database init failed:', err);
    process.exit(1);
  }
};

// Route: Login page
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '../Login/index.html'));
});

// Route: Signup page
app.get('/signup', (req, res) => {
  res.sendFile(path.join(__dirname, '../Sign/index.html'));
});

// Route: Forgot password page
app.get('/forgot-password', (req, res) => {
  res.sendFile(path.join(__dirname, '../Forgot_password/index.html'));
});

// Route: Dashboard (protected)
app.get('/dashboard', authenticateToken, (req, res) => {
  res.sendFile(path.join(__dirname, '../Dashboard/index.html'));
});

// API: Signup
app.post('/api/signup', upload.single('profilePicture'), async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  if (!validateEmail(email)) {
    return res.status(400).json({ error: 'Invalid email format' });
  }

  const existing = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
  if (existing.rows.length > 0) {
    return res.status(400).json({ error: 'Email already exists' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const profilePic = req.file ? req.file.buffer.toString('base64') : null;

  const result = await pool.query(
    'INSERT INTO users (name, email, password, profile_picture) VALUES ($1, $2, $3, $4) RETURNING id, name, email, profile_picture',
    [name, email, hashedPassword, profilePic]
  );

  const user = result.rows[0];

  const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: '1h' });

  res.cookie('token', token, {
    httpOnly: true,
    secure: false,
    sameSite: 'lax',
    maxAge: 3600000
  });

  res.status(201).json({
    message: 'Signup successful',
    user: {
      id: user.id,
      name: user.name,
      email: user.email,
      profilePicture: user.profile_picture
        ? `data:image/jpeg;base64,${user.profile_picture}`
        : null
    }
  });
});

// API: Login
app.post('/api/login', async (req, res) => {
  const { email, password, rememberMe } = req.body;

  const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
  const user = result.rows[0];
  if (!user) return res.status(400).json({ error: 'Email not found' });

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(400).json({ error: 'Incorrect password' });

  const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, {
    expiresIn: rememberMe ? '7d' : '1h'
  });

  res.cookie('token', token, {
    httpOnly: true,
    secure: false,
    sameSite: 'lax',
    maxAge: rememberMe ? 7 * 24 * 60 * 60 * 1000 : 60 * 60 * 1000
  });

  res.status(200).json({
    message: 'Login successful',
    user: {
      id: user.id,
      name: user.name,
      email: user.email,
      profilePicture: user.profile_picture
        ? `data:image/jpeg;base64,${user.profile_picture}`
        : null
    }
  });
});

// API: Forgot Password
app.post('/api/forgot-password', async (req, res) => {
  const { email, newPassword, confirmPassword } = req.body;

  if (!email || !newPassword || !confirmPassword) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  if (newPassword !== confirmPassword) {
    return res.status(400).json({ error: 'Passwords do not match' });
  }

  if (newPassword.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters' });
  }

  const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
  if (result.rows.length === 0) {
    return res.status(400).json({ error: 'Email not registered' });
  }

  const hashedPassword = await bcrypt.hash(newPassword, 10);
  await pool.query('UPDATE users SET password = $1 WHERE email = $2', [hashedPassword, email]);

  res.status(200).json({ message: 'Password reset successful' });
});

// API: Get current user (protected)
app.get('/api/user', authenticateToken, async (req, res) => {
  const result = await pool.query(
    'SELECT id, name, email, profile_picture FROM users WHERE email = $1',
    [req.user.email]
  );

  const user = result.rows[0];
  if (!user) return res.status(404).json({ error: 'User not found' });

  res.status(200).json({
    id: user.id,
    name: user.name,
    email: user.email,
    profilePicture: user.profile_picture
      ? `data:image/jpeg;base64,${user.profile_picture}`
      : null
  });
});

// API: Logout
app.post('/api/logout', (req, res) => {
  res.clearCookie('token');
  res.status(200).json({ message: 'Logout successful' });
});

// API: Test Protected
app.get('/api/protected', authenticateToken, (req, res) => {
  res.json({ message: 'You accessed protected route', user: req.user });
});

// Start Server
initDatabase().then(() => {
  app.listen(port, () => {
    console.log(`✅ Server running at http://13.221.233.193:${port}`);
  });
});

