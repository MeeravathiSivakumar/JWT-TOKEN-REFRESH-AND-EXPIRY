const express = require('express');
const router = express.Router();
const authenticate = require('../middlewares/authMiddleware');
const User = require('../models/User');

router.get('/me', authenticate, async (req, res) => {
  const user = await User.findById(req.userId).select('-passwordHash');
  res.json({ user });
});

module.exports = router;
