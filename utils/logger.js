// utils/logger.js
const winston = require('winston');

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console(),
    // For production, you'd save to a file or a dedicated logging service
    // new winston.transports.File({ filename: 'audit.log' })
  ],
});

module.exports = { logger };