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

const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require('@simplewebauthn/server');

const JWT_SECRET = process.env.JWT_SECRET;
const JWT_LIFETIME = process.env.JWT_LIFETIME;
const RP_ID = process.env.RP_ID || 'localhost';
const RP_NAME = process.env.RP_NAME || 'Knowledge Hub IAM';

function safeBase64UrlDecode(input, label = 'unknown') {
  try {
    if (typeof input === 'string') {
      return Buffer.from(input, 'base64url');
    } else if (input instanceof Uint8Array || ArrayBuffer.isView(input)) {
      return Buffer.from(input);
    } else if (input instanceof ArrayBuffer) {
      return Buffer.from(new Uint8Array(input));
    } else if (Buffer.isBuffer(input)) {
      return input;
    }
    throw new Error(`${label} is not a valid base64url-decodable value`);
  } catch (err) {
    console.error(`\u{1F4A5} Failed decoding ${label} (\"${input}\"):`, err.message);
    throw err;
  }
}

// @route   POST /api/auth/register
// @desc    Register a new user
// @access  Public
router.post('/register', async (req, res) => {
  const { username, email, password, customFields } = req.body;

  try {
    if (!username || !email) { // Password can be optional if passkey is intended for primary auth
      return res.status(400).json({ message: 'Please enter all required fields: username, email' });
    }
    if (password && password.length < 6) {
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
      password, // Password will be hashed by pre-save hook
      customFields: customFields || {},
      roles: ['user'],
      isVerified: false,
      emailVerificationToken: verificationToken,
      emailVerificationExpires: verificationExpires,
    });

    await user.save();
    logger.info(`User registered: ${user.username} (${user.email}) - ID: ${user.id}`);

    const verificationUrl = `${req.protocol}://${req.get('host')}/api/auth/verify-email/${verificationToken}`;
    const emailSent = await sendEmail({
      to: user.email,
      subject: 'Verify Your Email Address for Knowledge Hub IAM',
      htmlContent: `
        <p>Hello ${user.username},</p>
        <p>Thank you for registering with Knowledge Hub IAM.</p>
        <p>Please click this link to verify your email address: <a href="${verificationUrl}">${verificationUrl}</a></p>
        <p>This link will expire in 1 hour.</p>
        <p>If you did not register for an account, please ignore this email.</p>
        <p>Best regards,<br>The Knowledge Hub Team</p>
      `,
    });

    if (emailSent) {
      res.status(201).json({ message: 'User registered successfully. Please check your email to verify your account.' });
    } else {
      // If email sending fails, you might still register the user but inform them
      logger.error(`Failed to send verification email to ${user.email} after registration.`);
      res.status(202).json({ message: 'User registered, but failed to send verification email. Please try resending verification later.' });
    }

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
// @desc    Authenticate user & get token (password-based)
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
    const emailSent = await sendEmail({
      to: user.email,
      subject: 'Knowledge Hub IAM Password Reset Request',
      htmlContent: `
        <p>You requested a password reset for your Knowledge Hub IAM account.</p>
        <p>Please click this link to reset your password: <a href="${resetUrl}">${resetUrl}</a></p>
        <p>This link expires in 1 hour.</p>
        <p>If you did not request a password reset, please ignore this email.</p>
        <p>Best regards,<br>The Knowledge Hub Team</p>
      `,
    });

    if (emailSent) {
      res.status(200).json({ message: 'If an account with that email exists, a password reset link has been sent.' });
    } else {
      logger.error(`Failed to send password reset email to ${user.email}.`);
      res.status(500).json({ message: 'Server error: Failed to send password reset email.' });
    }

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

    user.password = newPassword; // Pre-save hook will hash this
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
// Remember to use a proper TOTP library like speakeasy or otplib for production
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
      qrCodeUrl: `https://api.qrserver.com/v1/create-qr-code/?size=150x150&data=otpauth://totp/IAM:${user.email}?secret=${encodeURIComponent(secret)}&issuer=${encodeURIComponent(RP_NAME)}`,
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

    // TODO: Replace with actual OTP verification using a library like speakeasy/otplib
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

// --- Passkey (WebAuthn) Registration ---
// @route   POST /api/auth/passkey/register/start
// @desc    Initiate passkey registration by generating challenge
// @access  Private (user must be logged in with password or another passkey)
router.post('/passkey/register/start', authenticateJWT, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ message: 'User not found' });
    const userIDBuffer = new TextEncoder().encode(user._id.toString());
    const options = await generateRegistrationOptions({
      rpName: RP_NAME,
      rpID: RP_ID,
      userID: userIDBuffer,
      userName: user.email,
      attestationType: 'none',
      excludeCredentials: user.passkeys.map(pk => ({
        id: Buffer.from(pk.credID, 'base64url'),
        type: 'public-key',
      })),
      authenticatorSelection: {
        residentKey: 'required',
        requireResidentKey: true,
        userVerification: 'preferred',
      },
      timeout: 60000,
    });
    req.session.currentChallenge = options.challenge;
    req.session.authenticatingUserID = user._id.toString();
    logger.info(`Passkey registration started for user: ${user.id}`);
    res.status(200).json(options);
  } catch (err) {
    logger.error(`Error starting passkey registration for user ${req.user.id}: ${err.message}`);
    res.status(500).json({ message: 'Server error initiating passkey registration.' });
  }
});

router.post('/passkey/register/finish', authenticateJWT, async (req, res) => {
  const { attestationResponse } = req.body;
  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ message: 'User not found' });

    const expectedChallenge = req.session?.currentChallenge;
    const authenticatingUserID = req.session?.authenticatingUserID;

    if (!expectedChallenge || authenticatingUserID !== user._id.toString()) {
      logger.warn(`Challenge mismatch or missing. Challenge=${expectedChallenge}, UserID=${authenticatingUserID}`);
      return res.status(400).json({ message: 'Registration challenge missing or user mismatch.' });
    }

    const origin = req.headers.origin;
    if (!origin) return res.status(400).json({ message: 'Origin header missing from request.' });

    logger.info(`Debug: Incoming attestationResponse.id: "${attestationResponse.id}" (Type: ${typeof attestationResponse.id})`);
    logger.info(`Debug: Incoming attestationResponse.response.attestationObject (Type: ${typeof attestationResponse.response.attestationObject})`);
    logger.info(`Debug: Incoming attestationResponse.response.clientDataJSON (Type: ${typeof attestationResponse.response.clientDataJSON})`);

    const backendAttestationResponse = {
      id: attestationResponse.id,
      rawId: attestationResponse.rawId,
      response: {
        attestationObject: safeBase64UrlDecode(attestationResponse.response.attestationObject, 'attestationObject'),
        clientDataJSON: safeBase64UrlDecode(attestationResponse.response.clientDataJSON, 'clientDataJSON'),
        transports: Array.isArray(attestationResponse.response.transports) ? attestationResponse.response.transports : [],
      },
      type: attestationResponse.type,
    };

    const { verified, registrationInfo } = await verifyRegistrationResponse({
      response: backendAttestationResponse,
      expectedChallenge,
      expectedOrigin: origin,
      expectedRPID: RP_ID,
      requireUserVerification: false,
    });

    if (!verified || !registrationInfo) return res.status(400).json({ message: 'Passkey registration failed.' });

    const canonicalCredID = registrationInfo.credentialID.toString('base64url');
    if (user.passkeys.some(pk => pk.credID === canonicalCredID)) {
      return res.status(400).json({ message: 'This passkey is already registered.' });
    }

    user.passkeys.push({
      publicKey: Buffer.from(registrationInfo.credentialPublicKey).toString('base64url'),
      credID: canonicalCredID,
      transports: backendAttestationResponse.response.transports,
      name: `Registered on ${new Date().toLocaleDateString()}`
    });

    await user.save();

    delete req.session.currentChallenge;
    delete req.session.authenticatingUserID;

    req.session.save(err => {
      if (err) console.error('Error saving session:', err);
      logger.info(`Passkey registered successfully for user: ${user.id}`);
      res.status(200).json({ message: 'Passkey registered successfully!' });
    });
  } catch (err) {
    logger.error(`Error finishing passkey registration for user ${req.user.id}: ${err.message}`);
    if (err.cause && err.cause.message) logger.error(`Verification error: ${err.cause.message}`);
    res.status(500).json({ message: 'Server error completing passkey registration.' });
  }
});
// --- Passkey (WebAuthn) Authentication ---
router.post('/passkey/login/start', async (req, res) => {
  // Debug log for incoming request
  console.log('--- /passkey/login/start ---');
  console.log('Request Headers (login start):', req.headers);
  console.log('Incoming Session ID (login start):', req.sessionID);
  console.log('Current Session (login start):', req.session);

  const { identifier } = req.body;
  try {
    const user = await User.findOne({ $or: [{ email: identifier }, { username: identifier }] });
    if (!user) {
      logger.warn(`Passkey login attempt for unknown identifier: ${identifier}`);
      return res.status(400).json({ message: 'Invalid identifier or no passkeys registered.' });
    }

    if (user.passkeys.length === 0) {
      logger.warn(`Passkey login attempt for user ${user.id} with no registered passkeys.`);
      return res.status(400).json({ message: 'No passkeys registered for this user.' });
    }

    const options = await generateAuthenticationOptions({
      rpID: RP_ID,
      userVerification: 'preferred',
      allowCredentials: user.passkeys.map(pk => ({
        id: Buffer.from(pk.credID, 'base64url'),
        type: 'public-key',
      })),
      timeout: 60000,
    });

    req.session.currentChallenge = options.challenge;
    req.session.authenticatingUserID = user._id.toString();

    req.session.save((err) => { // Explicitly save session
      if (err) console.error('Error saving session after login start:', err);
      logger.info(`Passkey authentication started for user: ${user.id}`);
      res.status(200).json(options);
    });

  } catch (err) {
    logger.error(`Error starting passkey login for identifier ${identifier}: ${err.message}`);
    res.status(500).json({ message: 'Server error initiating passkey login.' });
  }
});

router.post('/passkey/login/finish', async (req, res) => {
  console.log('--- /passkey/login/finish ---');
  console.log('Request Headers (login finish):', req.headers);
  console.log('Incoming Session ID (login finish):', req.sessionID);
  console.log('Current Session (login finish):', req.session);

  const { assertionResponse } = req.body;
  try {
    const expectedChallenge = req.session.currentChallenge;
    const authenticatingUserID = req.session.authenticatingUserID;

    if (!expectedChallenge || !authenticatingUserID) {
      logger.warn(`Authentication challenge mismatch or missing. Session: Challenge=${expectedChallenge}, UserID=${authenticatingUserID}.`);
      return res.status(400).json({ message: 'Authentication challenge missing or expired.' });
    }

    const user = await User.findById(authenticatingUserID);
    if (!user) return res.status(404).json({ message: 'User not found.' });

    // Received rawId from frontend, convert it to Base64URL string for lookup
    // Only decode for lookup, keep as string for simplewebauthn verification input
    const credentialIDBase64urlReceived = Buffer.from(safeBase64UrlDecode(assertionResponse.rawId, 'rawId for lookup')).toString('base64url');
    const registeredPasskey = user.passkeys.find(pk => pk.credID === credentialIDBase64urlReceived);

    if (!registeredPasskey) {
      logger.warn(`Authentication attempt with unregistered passkey ID for user ${user.id}`);
      return res.status(400).json({ message: 'Passkey not found or not registered for this user.' });
    }

    const origin = req.headers.origin;
    if (!origin) {
      logger.error(`Origin header missing in /passkey/login/finish request for user ${user.id}`);
      return res.status(400).json({ message: 'Origin header missing from request.' });
    }

    // --- CRITICAL FIX: Decode rawId here as well ---
    const backendAssertionResponse = {
      id: assertionResponse.id, // Keep as string
      rawId: safeBase64UrlDecode(assertionResponse.rawId, 'rawId'), // <--- ADDED safeBase64UrlDecode
      response: {
        ...assertionResponse.response,
        // These fields need to be converted to Buffers
        authenticatorData: safeBase64UrlDecode(assertionResponse.response.authenticatorData, 'authenticatorData'),
        clientDataJSON: safeBase64UrlDecode(assertionResponse.response.clientDataJSON, 'clientDataJSON'),
        signature: safeBase64UrlDecode(assertionResponse.response.signature, 'signature'),
        // userHandle can be null, so check before decoding
        userHandle: assertionResponse.response.userHandle ? safeBase64UrlDecode(assertionResponse.response.userHandle, 'userHandle') : null,
      }
    };

    const verification = await verifyAuthenticationResponse({
      response: backendAssertionResponse,
      expectedChallenge,
      expectedOrigin: origin,
      expectedRPID: RP_ID,
      authenticator: {
        credentialPublicKey: Buffer.from(registeredPasskey.publicKey, 'base64url'),
        credentialID: Buffer.from(registeredPasskey.credID, 'base64url'),
      },
      requireUserVerification: false,
    });

    const { verified, authenticationInfo } = verification;

    if (verified) {
      registeredPasskey.lastUsedAt = Date.now();
      await user.save();

      delete req.session.currentChallenge;
      delete req.session.authenticatingUserID;

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
          passkeys: user.passkeys.map(pk => ({
            credID: pk.credID,
            name: pk.name,
            createdAt: pk.createdAt,
            lastUsedAt: pk.lastUsedAt,
            transports: pk.transports
          })),
        },
      };

      req.session.save((err) => {
        if (err) console.error('Error saving session after login finish:', err);
        jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_LIFETIME }, (err, token) => {
          if (err) {
            logger.error(`JWT signing error after passkey login for user ${user.id}: ${err.message}`);
            throw err;
          }
          logger.info(`User logged in via passkey: ${user.email} - ID: ${user.id}`);
          res.json({ token, user: payload.user });
        });
      });

    } else {
      logger.warn(`Passkey authentication verification failed for user ${user.id}`);
      res.status(400).json({ message: 'Passkey authentication failed.' });
    }

  } catch (err) {
    logger.error(`Error finishing passkey login: ${err.message}`);
    if (err.cause && err.cause.message) {
      logger.error(`SimpleWebAuthn Verification Error Cause: ${err.cause.message}`);
    }
    res.status(500).json({ message: 'Server error completing passkey login.' });
  }
});

// @route   DELETE /api/auth/passkey/:credID
// @desc    Delete a specific passkey for the authenticated user
// @access  Private
router.delete('/passkey/:credID', authenticateJWT, async (req, res) => {
  try {
    const { credID } = req.params;
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ message: 'User not found' });

    // Remove the passkey from the user's array
    const initialPasskeyCount = user.passkeys.length;
    user.passkeys = user.passkeys.filter(pk => pk.credID !== credID);

    if (user.passkeys.length === initialPasskeyCount) {
      return res.status(404).json({ message: 'Passkey not found for this user.' });
    }

    // Optional: If you want to force users to have at least one password or passkey:
    // if (user.passkeys.length === 0 && !user.password) {
    //    return res.status(400).json({ message: 'Cannot remove last passkey if no password is set.' });
    // }

    await user.save();
    logger.info(`Passkey ${credID} removed for user: ${user.id}`);
    res.status(200).json({ message: 'Passkey removed successfully.' });
  } catch (err) {
    logger.error(`Error deleting passkey ${req.params.credID} for user ${req.user.id}: ${err.message}`);
    res.status(500).json({ message: 'Server error deleting passkey.' });
  }
});

module.exports = router;