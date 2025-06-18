// config/db.js
const mongoose = require('mongoose');
require('dotenv').config(); // Ensure dotenv is loaded for config files too

const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/iam_db';

const connectDB = async () => {
  try {
    await mongoose.connect(MONGO_URI);
    console.log('MongoDB connected successfully');
  } catch (err) {
    console.error('MongoDB connection error:', err.message);
    process.exit(1); // Exit process with failure
  }
};

module.exports = connectDB;