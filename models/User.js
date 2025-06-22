// models/User.js
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

// Schema for storing passkey (WebAuthn credential) information
const passkeySchema = new mongoose.Schema({
  publicKey: { type: String, required: true },
  credID: { type: String, required: true, unique: true, sparse: true }, // <--- ADD sparse: true HERE
  // For FIDO2 authenticators, you'd also track a "signature counter" to prevent replay attacks
  // counter: { type: Number, default: 0 },
  transports: { type: [String], default: [] }, // e.g., ['usb', 'nfc', 'ble', 'internal']
  name: { type: String, trim: true }, // Optional: User-given name for the passkey (e.g., "My Laptop's Face ID")
  createdAt: { type: Date, default: Date.now },
  lastUsedAt: { type: Date, default: Date.now },
});

const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
  },
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true,
    match: [/^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/, 'Please fill a valid email address'],
  },
  password: {
    type: String,
    required: function() {
      // Password is required if no passkeys are registered and user is not verified via other means
      // This allows passwordless registration initially, or if passkeys are disabled/removed
      return !this.passkeys || this.passkeys.length === 0;
    },
  },
  roles: {
    type: [String], // e.g., ['admin', 'user', 'manager']
    default: ['user'],
  },
  permissions: {
    type: [String], // e.g., ['read:users', 'write:products', 'delete:data']
    default: [],
  },
  isActive: {
    type: Boolean,
    default: true,
  },
  isVerified: { // For email verification
    type: Boolean,
    default: false,
  },
  emailVerificationToken: String,
  emailVerificationExpires: Date,
  passwordResetToken: String,
  passwordResetExpires: Date,
  twoFactorSecret: String, // For 2FA
  twoFactorEnabled: {
    type: Boolean,
    default: false,
  },
  passkeys: [passkeySchema], // Array of registered passkeys
  customFields: { // Flexible object to store custom user data
    type: mongoose.Schema.Types.Mixed,
    default: {},
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
  updatedAt: {
    type: Date,
    default: Date.now,
  },
});

// Pre-save hook to hash password
userSchema.pre('save', async function (next) {
  if (this.isModified('password') && this.password) {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
  }
  next();
});

// Method to compare password
userSchema.methods.comparePassword = async function (candidatePassword) {
  if (!this.password) return false;
  return await bcrypt.compare(candidatePassword, this.password);
};

// Update updatedAt field on every save
userSchema.pre('save', function (next) {
  this.updatedAt = Date.now();
  next();
});

const User = mongoose.model('User', userSchema);
module.exports = User;