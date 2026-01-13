const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    passwordHash: String, // Optional if using only OAuth
    googleId: String,
    googleId: String,
    googleTokens: { type: Object }, // access_token, refresh_token, expiry_date, etc.
    name: String,
    tier: { type: String, enum: ['starter', 'pro', 'enterprise', 'owner'], default: 'starter' },
    stripeCustomerId: String,
    roles: [{ type: String }],
    settings: { type: Map, of: String },
    lastLogin: Date,
    createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('User', UserSchema);
