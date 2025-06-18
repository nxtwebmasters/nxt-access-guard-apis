// middleware/authorization.js
const { logger } = require('../utils/logger');

const authorizeRoles = (...allowedRoles) => {
  return (req, res, next) => {
    if (!req.user || !req.user.roles) {
      logger.warn(`Unauthorized access attempt by user ${req.user ? req.user.id : 'unknown'} (no roles) to ${req.originalUrl}`);
      return res.status(403).json({ message: 'User not authorized (no roles found)' });
    }
    const hasRole = req.user.roles.some(role => allowedRoles.includes(role));
    if (hasRole) {
      next();
    } else {
      logger.warn(`Unauthorized access attempt by user ${req.user.id} (roles: ${req.user.roles.join(', ')}) to ${req.originalUrl}. Required: ${allowedRoles.join(', ')}`);
      res.status(403).json({ message: 'User not authorized (insufficient role)' });
    }
  };
};

const authorizePermissions = (...requiredPermissions) => {
  return (req, res, next) => {
    if (!req.user || !req.user.permissions) {
      logger.warn(`Unauthorized access attempt by user ${req.user ? req.user.id : 'unknown'} (no permissions) to ${req.originalUrl}`);
      return res.status(403).json({ message: 'User not authorized (no permissions found)' });
    }
    const hasPermission = requiredPermissions.every(perm => req.user.permissions.includes(perm));
    if (hasPermission) {
      next();
    } else {
      logger.warn(`Unauthorized access attempt by user ${req.user.id} (permissions: ${req.user.permissions.join(', ')}) to ${req.originalUrl}. Required: ${requiredPermissions.join(', ')}`);
      res.status(403).json({ message: 'User not authorized (insufficient permissions)' });
    }
  };
};

module.exports = { authorizeRoles, authorizePermissions };