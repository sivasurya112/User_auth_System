const User = require('../models/User');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const createToken = (user) => jwt.sign(
  { id: user._id, displayName: user.displayName },
  process.env.JWT_SECRET,
  { expiresIn: '1d' }
);

exports.signup = async (req, res) => {
  const { displayName, username, password } = req.body;
  try {
    const exists = await User.findOne({ username });
    if (exists) return res.status(400).json({ message: 'Username already taken' });

    const user = new User({ displayName, username, password });
    await user.save();

    const token = createToken(user);
    res.status(201).json({ token, displayName: user.displayName });
  } catch (err) {
    res.status(500).json({ message: 'Signup error', error: err.message });
  }
};

exports.login = async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await User.findOne({ username });
    if (!user) return res.status(400).json({ message: 'Invalid credentials' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });

    const token = createToken(user);
    res.status(200).json({ token, displayName: user.displayName });
  } catch (err) {
    res.status(500).json({ message: 'Login error', error: err.message });
  }
};

exports.protectedRoute = (req, res) => {
  res.status(200).json({ message: `🎉 Welcome ${req.user.displayName}!` });
};

// password reset logic remains unchanged...
