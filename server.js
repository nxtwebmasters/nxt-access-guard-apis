// server.js (Main application entry point)

// Polyfill globalThis.crypto if it's not already available (for Node.js 16.x and earlier)
if (typeof globalThis.crypto === 'undefined' || !globalThis.crypto.subtle) {
  try {
    const nodeCrypto = require('node:crypto');
    globalThis.crypto = nodeCrypto.webcrypto;
  } catch (e) {
    console.warn('Could not polyfill globalThis.crypto using node:crypto. Passkey features might fail if crypto API is truly unavailable.', e);
  }
}

const express = require('express');
const cors = require('cors');
require('dotenv').config(); // For environment variables
const connectDB = require('./config/db');
const { logger } = require('./utils/logger');
const authRoutes = require('./routes/auth');
const userRoutes = require('./routes/users');
const { loginLimiter, apiLimiter } = require('./middleware/rateLimit');

const session = require('express-session'); // For session management (needed for WebAuthn challenges)
const MongoStore = require('connect-mongo'); // To store sessions in MongoDB
const morgan = require('morgan'); // Import morgan for detailed request logging

const app = express();
const PORT = process.env.PORT || 5000;
const MONGO_URI = process.env.MONGO_URI; // Ensure MONGO_URI is accessible here for session store

// Add Morgan for request logging - very helpful for debugging headers
app.use(morgan('dev')); // 'dev' format provides concise output

// Global Middleware
app.use(cors({
  origin: 'http://localhost:4200', // Explicitly allow your frontend origin
  credentials: true, // Allow cookies/sessions to be sent
}));
app.use(express.json()); // Parses JSON bodies of incoming requests

// Configure express-session for WebAuthn challenge storage
app.use(session({
  secret: process.env.EXPRESS_SESSION_SECRET || 'super_secret_session_key', // A strong, random key
  resave: false, // Don't save session if unmodified
  saveUninitialized: false, // Don't create session until something stored
  store: MongoStore.create({
    mongoUrl: MONGO_URI,
    ttl: 14 * 24 * 60 * 60, // Session will expire after 14 days (default)
    autoRemove: 'interval', // Remove expired sessions every `autoRemoveInterval`
    autoRemoveInterval: 60, // In minutes. Checks for expired sessions every 60 minutes
    collectionName: 'sessions', // Name of the collection in MongoDB to store sessions
  }),
  cookie: {
    maxAge: 1000 * 60 * 60 * 24 * 7, // 7 days (in milliseconds)
    httpOnly: true, // Prevents client-side JS from reading the cookie
    // In development (NODE_ENV is not 'production'), we use HTTP (secure: false).
    // For `SameSite=None`, `secure: true` is mandatory.
    // Therefore, for HTTP localhost cross-port, we cannot use `SameSite: 'none'`.
    // We explicitly set `secure: false` for dev and rely on browser default for `SameSite`
    // (which is typically 'Lax' and *might* work for localhost cross-port, or implicitly omit it).
    // If issues persist, the only reliable way is local HTTPS or proxy (which you're doing).
    secure: process.env.NODE_ENV === 'production' ? true : false,
    sameSite: process.env.NODE_ENV === 'production' ? 'lax' : 'lax', // Stick to 'lax' for dev. `None` is problematic over HTTP.
  },
}));


// Apply general API rate limiting to all /api routes except login
app.use('/api', apiLimiter);
// Apply specific login rate limiting
app.use('/api/auth/login', loginLimiter);
app.use('/api/auth/passkey/login/start', loginLimiter); // Also apply to passkey login start

// Function to start the server after DB connection
const startServer = async () => {
  try {
    await connectDB(); // Await the database connection before mounting routes

    // Route Middleware - These are mounted AFTER the DB connection is established
    app.use('/api/auth', authRoutes);
    app.use('/api/users', userRoutes);

    // Basic health check route
    app.get('/', (req, res) => {
      res.send('IAM Backend is running!');
    });

    app.listen(PORT, () => logger.info(`Server running on port ${PORT}`));
  } catch (err) {
    logger.error('Failed to start server due to database connection error:', err);
    process.exit(1); // Exit process with failure
  }
};

startServer(); // Call the async function to start the server