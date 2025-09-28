const mongoose = require('mongoose');

const RefreshTokenSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  token: { type: String, required: true, unique: true },
  createdAt: { type: Date, default: Date.now }
});

// Optionally set TTL index if you want DB-driven expiry:
// RefreshTokenSchema.index({ createdAt: 1 }, { expireAfterSeconds: 60 * 60 * 24 * 7 });

module.exports = mongoose.model('RefreshToken', RefreshTokenSchema);
