// server.js (Main application entry point)
const express = require('express');
const cors = require('cors');
require('dotenv').config(); // For environment variables
const connectDB = require('./config/db');
const { logger } = require('./utils/logger');
const authRoutes = require('./routes/auth');
const userRoutes = require('./routes/users');
const { loginLimiter, apiLimiter } = require('./middleware/rateLimit');

const app = express();
const PORT = process.env.PORT || 5000;

// Global Middleware
app.use(cors()); // Allows cross-origin requests
app.use(express.json()); // Parses JSON bodies of incoming requests

// Apply general API rate limiting to all /api routes except login
app.use('/api', apiLimiter);
// Apply specific login rate limiting
app.use('/api/auth/login', loginLimiter);

// Function to start the server after DB connection
const startServer = async () => {
  try {
    await connectDB(); // Await the database connection before mounting routes
    
    // Route Middleware - These are mounted AFTER the DB connection is established
    app.use('/api/auth', authRoutes);
    app.use('/api/users', userRoutes);

    app.listen(PORT, () => logger.info(`Server running on port ${PORT}`));
  } catch (err) {
    logger.error('Failed to start server due to database connection error:', err);
    process.exit(1); // Exit process with failure
  }
};

startServer(); // Call the async function to start the server