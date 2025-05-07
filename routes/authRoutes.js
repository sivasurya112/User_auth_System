const express = require('express');
const router = express.Router();
const {
  signup,
  login,
  protectedRoute,
  requestPasswordReset,
  resetPassword
} = require('../controllers/authController');
const requireAuth = require('../middleware/requireAuth');

router.post('/signup', signup);
router.post('/login', login);
router.get('/protected', requireAuth, protectedRoute);
router.post('/request-reset', requestPasswordReset);
router.post('/reset-password/:token', resetPassword);

module.exports = router;
