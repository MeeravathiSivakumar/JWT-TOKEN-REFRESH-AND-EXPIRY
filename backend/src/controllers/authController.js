const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const User = require('../models/User');
const RefreshToken = require('../models/RefreshToken');

const ACCESS_EXP = process.env.ACCESS_TOKEN_EXPIRY || '15m';
const REFRESH_EXP = process.env.REFRESH_TOKEN_EXPIRY || '7d';

function signAccessToken(payload) {
  return jwt.sign(payload, process.env.ACCESS_TOKEN_SECRET, { expiresIn: ACCESS_EXP });
}
function signRefreshToken(payload) {
  return jwt.sign(payload, process.env.REFRESH_TOKEN_SECRET, { expiresIn: REFRESH_EXP });
}

function setRefreshCookie(res, token) {
  res.cookie('jid', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'Strict',
    maxAge: 1000 * 60 * 60 * 24 * 7 // 7 days
  });
}

exports.register = async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ message: 'Missing fields' });

    const exists = await User.findOne({ username });
    if (exists) return res.status(409).json({ message: 'User exists' });

    const hash = await bcrypt.hash(password, 10);
    const user = new User({ username, passwordHash: hash });
    await user.save();
    res.status(201).json({ message: 'User created' });
  } catch (e) { console.error(e); res.status(500).json({ message: 'Server error' }); }
};

exports.login = async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user) return res.status(401).json({ message: 'Invalid credentials' });

    const ok = await user.comparePassword(password);
    if (!ok) return res.status(401).json({ message: 'Invalid credentials' });

    const accessToken = signAccessToken({ userId: user._id });
    const refreshToken = signRefreshToken({ userId: user._id });

    await RefreshToken.create({ userId: user._id, token: refreshToken });
    setRefreshCookie(res, refreshToken);
    res.json({ accessToken });
  } catch (e) { console.error(e); res.status(500).json({ message: 'Server error' }); }
};

exports.refresh = async (req, res) => {
  try {
    const token = req.cookies.jid;
    if (!token) return res.status(401).json({ message: 'No token' });

    const stored = await RefreshToken.findOne({ token });
    if (!stored) return res.status(403).json({ message: 'Invalid token' });

    jwt.verify(token, process.env.REFRESH_TOKEN_SECRET, async (err, payload) => {
      if (err) {
        await stored.remove().catch(()=>{});
        return res.status(403).json({ message: 'Invalid token' });
      }

      // Rotate refresh token
      await stored.remove();
      const newRefreshToken = signRefreshToken({ userId: payload.userId });
      await RefreshToken.create({ userId: payload.userId, token: newRefreshToken });

      const newAccessToken = signAccessToken({ userId: payload.userId });
      setRefreshCookie(res, newRefreshToken);
      res.json({ accessToken: newAccessToken });
    });
  } catch (e) { console.error(e); res.status(500).json({ message: 'Server error' }); }
};

exports.logout = async (req, res) => {
  try {
    const token = req.cookies.jid;
    if (token) await RefreshToken.deleteOne({ token }).catch(()=>{});
    res.clearCookie('jid');
    res.json({ message: 'Logged out' });
  } catch (e) { console.error(e); res.status(500).json({ message: 'Server error' }); }
};
