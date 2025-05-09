require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const crypto = require('crypto');
const path = require('path');
const User = require('./models/User'); // Adjust the path if needed

const app = express();
const PORT = 3000;
const JWT_SECRET = 'super-secret-key';
const RESET_TOKEN_EXPIRY = 1000 * 60 * 15; // 15 minutes

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ✅ Connect to MongoDB
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log('✅ Connected to MongoDB'))
.catch(err => console.error('MongoDB connection error:', err));

// ✅ Utility Functions
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

// ✅ Signup Route
app.post('/api/auth/signup', async (req, res) => {
  const { username, password, displayName } = req.body;
  if (!username || !password || !displayName) {
    return res.status(400).json({ message: 'Username, password, and display name are required' });
  }

  const existingUser = await User.findOne({ username });
  if (existingUser) return res.status(409).json({ message: 'Username already taken' });

  if (!isStrongPassword(password)) {
    return res.status(400).json({ message: 'Password must be strong (8+ chars, uppercase, lowercase, number, special char).' });
  }

  const user = new User({ username, displayName, password });
  await user.save();

  const token = generateToken(user);
  res.json({ token, displayName });
});

// ✅ Login Route
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });
  if (!user) return res.status(404).json({ message: 'User not found' });

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return res.status(401).json({ message: 'Incorrect password' });

  const token = generateToken(user);
  res.json({ token, displayName: user.displayName });
});

// ✅ Protected Route
app.get('/api/auth/protected', authenticateToken, (req, res) => {
  res.json({ message: `Hello ${req.user.displayName}, this is protected content!` });
});

// ✅ Password Reset Request
app.post('/api/auth/request-reset', async (req, res) => {
  const { username } = req.body;
  const user = await User.findOne({ username });
  if (!user) return res.status(404).json({ message: 'User not found' });

  const token = crypto.randomBytes(20).toString('hex');
  user.resetToken = token;
  user.resetTokenExpiry = Date.now() + RESET_TOKEN_EXPIRY;
  await user.save();

  const resetLink = `http://localhost:${PORT}/api/auth/reset-password/${token}`;
  console.log(`🔐 Reset link for ${username}: ${resetLink}`);
  res.json({ message: 'Reset link generated (check console)', resetLink });
});

// ✅ Password Reset Confirmation
app.post('/api/auth/reset-password/:token', async (req, res) => {
  const { token } = req.params;
  const { password } = req.body;

  if (!isStrongPassword(password)) {
    return res.status(400).json({ message: 'Password must be strong (8+ chars, uppercase, lowercase, number, special char).' });
  }

  const user = await User.findOne({ resetToken: token, resetTokenExpiry: { $gt: Date.now() } });
  if (!user) return res.status(400).json({ message: 'Invalid or expired token' });

  user.password = password;
  user.resetToken = null;
  user.resetTokenExpiry = null;
  await user.save();

  res.json({ message: 'Password successfully reset' });
});

// ✅ Serve Frontend for Unknown Routes
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'app.html'));
});

// ✅ Start Server
app.listen(PORT, () => {
  console.log(`✅ Server running at http://localhost:${PORT}`);
});
