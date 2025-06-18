// routes/auth.js
const express = require('express');
const router = express.Router();
const User = require('../models/User');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const authenticateJWT = require('../middleware/auth');
const { logger } = require('../utils/logger');
const { sendEmail } = require('../utils/emailService');
require('dotenv').config();

const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret_key';
const JWT_LIFETIME = process.env.JWT_LIFETIME || '1h';

// @route   POST /api/auth/register
// @desc    Register a new user
// @access  Public
router.post('/register', async (req, res) => {
  const { username, email, password, customFields } = req.body;

  try {
    if (!username || !email || !password) {
      return res.status(400).json({ message: 'Please enter all required fields: username, email, password' });
    }
    if (password.length < 6) {
        return res.status(400).json({ message: 'Password must be at least 6 characters long' });
    }

    let user = await User.findOne({ $or: [{ email }, { username }] });
    if (user) {
      return res.status(400).json({ message: 'User already exists with this email or username' });
    }

    const verificationToken = crypto.randomBytes(32).toString('hex');
    const verificationExpires = new Date(Date.now() + 3600000); // 1 hour expiration

    user = new User({
      username,
      email,
      password,
      customFields: customFields || {},
      roles: ['user'],
      isVerified: false,
      emailVerificationToken: verificationToken,
      emailVerificationExpires: verificationExpires,
    });

    await user.save();
    logger.info(`User registered: ${user.username} (${user.email}) - ID: ${user.id}`);

    const verificationUrl = `${req.protocol}://${req.get('host')}/api/auth/verify-email/${verificationToken}`;
    await sendEmail({
      to: user.email,
      subject: 'Verify Your Email Address',
      htmlContent: `<p>Please click this link to verify your email: <a href="${verificationUrl}">${verificationUrl}</a></p><p>This link expires in 1 hour.</p>`,
    });

    res.status(201).json({ message: 'User registered successfully. Please check your email to verify your account.' });

  } catch (err) {
    logger.error(`Registration error: ${err.message}`, { username, email, ip: req.ip });
    res.status(500).send('Server error during registration');
  }
});

// @route   GET /api/auth/verify-email/:token
// @desc    Verify user email using token
// @access  Public
router.get('/verify-email/:token', async (req, res) => {
  try {
    const { token } = req.params;

    const user = await User.findOne({
      emailVerificationToken: token,
      emailVerificationExpires: { $gt: Date.now() },
    });

    if (!user) {
      return res.status(400).json({ message: 'Invalid or expired verification token.' });
    }

    user.isVerified = true;
    user.emailVerificationToken = undefined;
    user.emailVerificationExpires = undefined;
    await user.save();

    logger.info(`User email verified: ${user.email} - ID: ${user.id}`);
    res.status(200).json({ message: 'Email successfully verified. You can now log in.' });

  } catch (err) {
    logger.error(`Email verification error: ${err.message}`, { token, ip: req.ip });
    res.status(500).send('Server error during email verification');
  }
});

// @route   POST /api/auth/login
// @desc    Authenticate user & get token
// @access  Public
router.post('/login', async (req, res) => {
  const { identifier, password } = req.body;

  try {
    if (!identifier || !password) {
        return res.status(400).json({ message: 'Please provide identifier and password' });
    }

    let user = await User.findOne({ $or: [{ email: identifier }, { username: identifier }] });

    if (!user) {
      logger.warn(`Failed login attempt for identifier: ${identifier} - User not found`);
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    if (!user.isActive) {
      logger.warn(`Login attempt for inactive user: ${user.email}`);
      return res.status(403).json({ message: 'Account is inactive. Please contact support.' });
    }

    if (!user.isVerified) {
        logger.warn(`Login attempt for unverified email: ${user.email}`);
        return res.status(403).json({ message: 'Please verify your email address to log in.' });
    }

    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      logger.warn(`Failed login attempt for user: ${user.email} - Invalid password`);
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    const payload = {
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        roles: user.roles,
        permissions: user.permissions,
        customFields: user.customFields,
        isVerified: user.isVerified,
        twoFactorEnabled: user.twoFactorEnabled,
      },
    };

    jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_LIFETIME }, (err, token) => {
      if (err) {
        logger.error(`JWT signing error for user ${user.id}: ${err.message}`);
        throw err;
      }
      logger.info(`User logged in: ${user.email} - ID: ${user.id}`);
      res.json({ token, user: payload.user });
    });

  } catch (err) {
    logger.error(`Login server error: ${err.message}`, { identifier, ip: req.ip });
    res.status(500).send('Server error during login');
  }
});

// @route   GET /api/auth/verify-token
// @desc    Verify current user's token and return user data
// @access  Private
router.get('/verify-token', authenticateJWT, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    if (!user) {
      logger.warn(`Token verification failed - User ${req.user.id} not found.`);
      return res.status(404).json({ message: 'User not found' });
    }
    logger.info(`Token verified for user: ${user.email} - ID: ${user.id}`);
    res.json({ message: 'Token is valid', user });
  } catch (err) {
    logger.error(`Server error during token verification for user ${req.user ? req.user.id : 'unknown'}: ${err.message}`);
    res.status(500).send('Server error during token verification');
  }
});

// @route   POST /api/auth/forgot-password
// @desc    Request password reset link
// @access  Public
router.post('/forgot-password', async (req, res) => {
  const { email } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) {
      logger.info(`Forgot password request for unknown email: ${email}`);
      return res.status(200).json({ message: 'If an account with that email exists, a password reset link has been sent.' });
    }

    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetExpires = new Date(Date.now() + 3600000); // 1 hour expiration

    user.passwordResetToken = resetToken;
    user.passwordResetExpires = resetExpires;
    await user.save();

    logger.info(`Password reset token generated for user: ${user.email} - ID: ${user.id}`);

    const resetUrl = `${req.protocol}://${req.get('host')}/reset-password/${resetToken}`;
    await sendEmail({
      to: user.email,
      subject: 'Password Reset Request',
      htmlContent: `<p>You requested a password reset. Please click this link to reset your password: <a href="${resetUrl}">${resetUrl}</a></p><p>This link expires in 1 hour.</p>`,
    });

    res.status(200).json({ message: 'If an account with that email exists, a password reset link has been sent.' });

  } catch (err) {
    logger.error(`Forgot password error: ${err.message}`, { email, ip: req.ip });
    res.status(500).send('Server error during forgot password request');
  }
});

// @route   POST /api/auth/reset-password/:token
// @desc    Reset user password using token
// @access  Public
router.post('/reset-password/:token', async (req, res) => {
  const { token } = req.params;
  const { newPassword } = req.body;

  try {
    if (!newPassword || newPassword.length < 6) {
      return res.status(400).json({ message: 'New password must be at least 6 characters long.' });
    }

    const user = await User.findOne({
      passwordResetToken: token,
      passwordResetExpires: { $gt: Date.now() },
    });

    if (!user) {
      logger.warn(`Password reset failed - Invalid or expired token: ${token}`);
      return res.status(400).json({ message: 'Invalid or expired password reset token.' });
    }

    user.password = newPassword;
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save();

    logger.info(`Password successfully reset for user: ${user.email} - ID: ${user.id}`);
    res.status(200).json({ message: 'Password has been reset successfully. You can now log in with your new password.' });

  } catch (err) {
    logger.error(`Password reset error: ${err.message}`, { token, ip: req.ip });
    res.status(500).send('Server error during password reset');
  }
});

// --- 2FA Setup (Conceptual) ---
router.post('/2fa/generate-secret', authenticateJWT, async (req, res) => {
    try {
        const user = await User.findById(req.user.id);
        if (!user) return res.status(404).json({ message: 'User not found' });
        if (user.twoFactorEnabled) return res.status(400).json({ message: '2FA is already enabled.' });

        const secret = crypto.randomBytes(16).toString('base64');
        user.twoFactorSecret = secret;
        await user.save();

        logger.info(`2FA secret generated for user: ${user.id}`);
        res.status(200).json({
            message: '2FA secret generated. Scan QR code and verify.',
            secret: secret,
            qrCodeUrl: `https://api.qrserver.com/v1/create-qr-code/?size=150x150&data=otpauth://totp/IAM:${user.email}?secret=${encodeURIComponent(secret)}`,
        });
    } catch (err) {
        logger.error(`Error generating 2FA secret for user ${req.user.id}: ${err.message}`);
        res.status(500).json({ message: 'Server error generating 2FA secret.' });
    }
});

router.post('/2fa/verify-and-enable', authenticateJWT, async (req, res) => {
    const { otp } = req.body;
    try {
        const user = await User.findById(req.user.id);
        if (!user) return res.status(404).json({ message: 'User not found' });
        if (!user.twoFactorSecret) return res.status(400).json({ message: '2FA secret not generated.' });

        const verified = otp === '123456'; // Placeholder for OTP verification (ALWAYS USE A REAL LIBRARY)

        if (verified) {
            user.twoFactorEnabled = true;
            await user.save();
            logger.info(`2FA enabled for user: ${user.id}`);
            res.status(200).json({ message: '2FA enabled successfully!' });
        } else {
            logger.warn(`2FA verification failed for user ${req.user.id} with OTP: ${otp}`);
            res.status(400).json({ message: 'Invalid OTP.' });
        }
    } catch (err) {
        logger.error(`Error verifying 2FA for user ${req.user.id}: ${err.message}`);
        res.status(500).json({ message: 'Server error enabling 2FA.' });
    }
});

router.post('/2fa/disable', authenticateJWT, async (req, res) => {
    try {
        const user = await User.findById(req.user.id);
        if (!user) return res.status(404).json({ message: 'User not found' });
        if (!user.twoFactorEnabled) return res.status(400).json({ message: '2FA is not enabled.' });

        user.twoFactorEnabled = false;
        user.twoFactorSecret = undefined;
        await user.save();
        logger.info(`2FA disabled for user: ${user.id}`);
        res.status(200).json({ message: '2FA disabled successfully!' });
    } catch (err) {
        logger.error(`Error disabling 2FA for user ${req.user.id}: ${err.message}`);
        res.status(500).json({ message: 'Server error disabling 2FA.' });
    }
});

module.exports = router;