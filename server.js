const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const crypto = require('crypto');
const path = require('path');

const app = express();
const PORT = 3000;
const JWT_SECRET = 'super-secret-key';
const RESET_TOKEN_EXPIRY = 1000 * 60 * 15; // 15 minutes

app.use(cors());
app.use(express.json());

// Serve frontend files from "public" folder
app.use(express.static(path.join(__dirname, 'public')));

const users = [];

function generateToken(user) {
  return jwt.sign({ username: user.username, displayName: user.displayName }, JWT_SECRET, { expiresIn: '2h' });
}

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Token required' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid token' });
    req.user = user;
    next();
  });
}
function isStrongPassword(password) {
  const strongRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$/;
  return strongRegex.test(password);
}

app.post('/api/auth/signup', async (req, res) => {
  const { username, password, displayName } = req.body;
  if (!username || !password || !displayName) {
    return res.status(400).json({ message: 'Username, password, and display name are required' });
  }

  const existingUser = users.find(u => u.username === username);
  if (existingUser) return res.status(409).json({ message: 'Username already taken' });

  const passwordHash = await bcrypt.hash(password, 10);
  const user = { username, displayName, passwordHash };
  users.push(user);

  const token = generateToken(user);
  res.json({ token, displayName });
});

app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username);
  if (!user) return res.status(404).json({ message: 'User not found' });

  const isMatch = await bcrypt.compare(password, user.passwordHash);
  if (!isMatch) return res.status(401).json({ message: 'Incorrect password' });

  const token = generateToken(user);
  res.json({ token, displayName: user.displayName });
});

app.get('/api/auth/protected', authenticateToken, (req, res) => {
  res.json({ message: `Hello ${req.user.displayName}, this is protected content!` });
});

app.post('/api/auth/request-reset', (req, res) => {
  const { username } = req.body;
  const user = users.find(u => u.username === username);
  if (!user) return res.status(404).json({ message: 'User not found' });

  const token = crypto.randomBytes(20).toString('hex');
  user.resetToken = token;
  user.resetTokenExpiry = Date.now() + RESET_TOKEN_EXPIRY;

  const resetLink = `http://localhost:${PORT}/api/auth/reset-password/${token}`;
  console.log(`🔐 Reset link for ${username}: ${resetLink}`);
  res.json({ message: 'Reset link generated (check console)', resetLink });
});

app.post('/api/auth/reset-password/:token', async (req, res) => {
  const { token } = req.params;
  const { password } = req.body;
  if (!isStrongPassword(password)) {
    return res.status(400).json({ message: 'Password is too weak. Must include uppercase, lowercase, number, special character, and be at least 8 characters.' });
  }
  const user = users.find(u => u.resetToken === token && u.resetTokenExpiry > Date.now());
  if (!user) return res.status(400).json({ message: 'Invalid or expired token' });

  user.passwordHash = await bcrypt.hash(password, 10);
  user.resetToken = null;
  user.resetTokenExpiry = null;

  res.json({ message: 'Password successfully reset' });
});

// Fallback to serve index.html for any unknown route (for SPA routing)
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'app.html'));
});

app.listen(PORT, () => {
  console.log(`✅ Server running at http://localhost:${PORT}`);
});
