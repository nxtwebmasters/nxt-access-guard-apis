// routes/users.js
const express = require('express');
const router = express.Router();
const User = require('../models/User');
const authenticateJWT = require('../middleware/auth');
const { authorizeRoles } = require('../middleware/authorization');
const { logger } = require('../utils/logger');
const bcrypt = require('bcryptjs'); // Needed for password hashing in change-password route

// @route   GET /api/users
// @desc    Get all users (Admin only)
// @access  Private (Admin role)
router.get('/', authenticateJWT, authorizeRoles('admin'), async (req, res) => {
  try {
    const users = await User.find().select('-password -emailVerificationToken -passwordResetToken -twoFactorSecret');
    logger.info(`Admin user ${req.user.id} fetched all users.`);
    res.json(users);
  } catch (err) {
    logger.error(`Error fetching all users by admin ${req.user.id}: ${err.message}`);
    res.status(500).send('Server error fetching users');
  }
});

// @route   GET /api/users/:id
// @desc    Get user by ID (Admin or self)
// @access  Private (Admin role or user's own ID)
router.get('/:id', authenticateJWT, async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select('-password -emailVerificationToken -passwordResetToken -twoFactorSecret');
    if (!user) {
      logger.warn(`User ${req.user.id} attempted to view non-existent user profile ${req.params.id}`);
      return res.status(404).json({ message: 'User not found' });
    }

    if (req.user.id === req.params.id || req.user.roles.includes('admin')) {
      logger.info(`User ${req.user.id} viewed profile of user ${req.params.id}`);
      res.json(user);
    } else {
      logger.warn(`Unauthorized attempt by user ${req.user.id} to view profile of user ${req.params.id}`);
      res.status(403).json({ message: 'Not authorized to view this user profile' });
    }
  } catch (err) {
    logger.error(`Server error fetching user ${req.params.id} by user ${req.user.id}: ${err.message}`);
    if (err.kind === 'ObjectId') {
      return res.status(400).json({ message: 'Invalid user ID format' });
    }
    res.status(500).send('Server error fetching user');
  }
});

// @route   PUT /api/users/:id
// @desc    Update user by ID (Admin or self for certain fields)
// @access  Private (Admin role or user's own ID)
router.put('/:id', authenticateJWT, async (req, res) => {
  const { username, email, roles, permissions, isActive, isVerified, customFields } = req.body;

  const updateFields = {};
  if (username) updateFields.username = username;
  if (email) updateFields.email = email;
  if (customFields) updateFields.customFields = customFields;

  try {
    let user = await User.findById(req.params.id);
    if (!user) {
      logger.warn(`Update attempt on non-existent user ${req.params.id} by user ${req.user.id}`);
      return res.status(404).json({ message: 'User not found' });
    }

    if (req.user.roles.includes('admin')) {
      if (roles) updateFields.roles = roles;
      if (permissions) updateFields.permissions = permissions;
      if (typeof isActive === 'boolean') updateFields.isActive = isActive;
      if (typeof isVerified === 'boolean') updateFields.isVerified = isVerified;
    } else if (req.user.id !== req.params.id) {
      logger.warn(`Unauthorized update attempt by user ${req.user.id} on user ${req.params.id}`);
      return res.status(403).json({ message: 'Not authorized to update this user profile' });
    }

    if (req.user.id === req.params.id && (roles || permissions || typeof isActive === 'boolean' || typeof isVerified === 'boolean')) {
        if (!req.user.roles.includes('admin')) {
            logger.warn(`User ${req.user.id} attempted to change own roles/permissions/status.`);
            return res.status(403).json({ message: 'You are not authorized to change your own roles, permissions, active, or verified status.' });
        }
    }

    user = await User.findByIdAndUpdate(
      req.params.id,
      { $set: updateFields },
      { new: true, runValidators: true }
    ).select('-password -emailVerificationToken -passwordResetToken -twoFactorSecret');

    logger.info(`User ${req.user.id} updated user ${req.params.id}. Changed fields: ${Object.keys(updateFields).join(', ')}`);
    res.json({ message: 'User updated successfully', user });

  } catch (err) {
    logger.error(`Server error updating user ${req.params.id} by user ${req.user.id}: ${err.message}`);
    if (err.code === 11000) {
        return res.status(400).json({ message: 'Username or email already exists.' });
    }
    res.status(500).send('Server error updating user');
  }
});

// @route   DELETE /api/users/:id
// @desc    Delete user by ID (Admin only)
// @access  Private (Admin role)
router.delete('/:id', authenticateJWT, authorizeRoles('admin'), async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) {
      logger.warn(`Delete attempt on non-existent user ${req.params.id} by admin ${req.user.id}`);
      return res.status(404).json({ message: 'User not found' });
    }
    await user.deleteOne();
    logger.info(`Admin ${req.user.id} deleted user ${req.params.id} (${user.email}).`);
    res.json({ message: 'User removed successfully' });
  } catch (err) {
    logger.error(`Server error deleting user ${req.params.id} by admin ${req.user.id}: ${err.message}`);
    res.status(500).send('Server error deleting user');
  }
});

// @route   PUT /api/users/:id/change-password
// @desc    Change user password (self or admin)
// @access  Private
router.put('/:id/change-password', authenticateJWT, async (req, res) => {
    const { oldPassword, newPassword } = req.body;

    try {
        let user = await User.findById(req.params.id);
        if (!user) {
            logger.warn(`Password change attempt for non-existent user ${req.params.id} by user ${req.user.id}`);
            return res.status(404).json({ message: 'User not found' });
        }

        if (req.user.id !== req.params.id && !req.user.roles.includes('admin')) {
            logger.warn(`Unauthorized password change attempt by user ${req.user.id} for user ${req.params.id}`);
            return res.status(403).json({ message: 'Not authorized to change this user\'s password' });
        }

        if (req.user.id === req.params.id) {
            if (!oldPassword) {
                return res.status(400).json({ message: 'Old password is required to change your password' });
            }
            const isMatch = await user.comparePassword(oldPassword);
            if (!isMatch) {
                logger.warn(`Failed self-password change for user ${req.user.id} - old password mismatch`);
                return res.status(400).json({ message: 'Old password does not match' });
            }
        }

        if (!newPassword || newPassword.length < 6) {
            return res.status(400).json({ message: 'New password must be at least 6 characters long.' });
        }

        user.password = newPassword;
        await user.save();

        logger.info(`Password changed for user ${user.email} (ID: ${user.id}) by ${req.user.id === user.id ? 'themselves' : `admin ${req.user.id}`}`);
        res.json({ message: 'Password updated successfully' });

    } catch (err) {
        logger.error(`Server error changing password for user ${req.params.id}: ${err.message}`);
        res.status(500).send('Server error changing password');
    }
});

module.exports = router;