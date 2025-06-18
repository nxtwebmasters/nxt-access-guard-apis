// middleware/auth.js
const jwt = require('jsonwebtoken');
const { logger } = require('../utils/logger');
require('dotenv').config();

const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret_key'; // CHANGE THIS IN PRODUCTION

const authenticateJWT = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'No token, authorization denied' });
  }

  const token = authHeader.split(' ')[1];

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded.user; // Attach user payload to request
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      logger.warn(`Expired token attempt from IP: ${req.ip}`);
      return res.status(403).json({ message: 'Token expired' });
    }
    logger.error(`Invalid token attempt from IP: ${req.ip}, Error: ${err.message}`);
    res.status(401).json({ message: 'Token is not valid' });
  }
};

module.exports = authenticateJWT;