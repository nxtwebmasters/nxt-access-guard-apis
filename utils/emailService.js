// utils/emailService.js
const { logger } = require('./logger');
const nodemailer = require('nodemailer');
require('dotenv').config();

const EMAIL_USER = process.env.EMAIL_USER;
const EMAIL_PASS = process.env.EMAIL_PASS;

let transporter;

const createTransporter = () => {
  if (!EMAIL_USER || !EMAIL_PASS) {
    logger.error('Email sending is not configured: EMAIL_USER or EMAIL_PASS environment variables are missing.');
    console.log('--- EMAIL CONFIGURATION ERROR ---');
    console.log('Please ensure EMAIL_USER and EMAIL_PASS are set in your .env file for actual email sending.');
    console.log('---------------------------------');
    return null; // Return null if configuration is missing
  }

  if (!transporter) {
    transporter = nodemailer.createTransport({
      service: 'gmail', // For Gmail. For other services, you might need specific host, port, secure options.
      auth: {
        user: EMAIL_USER,
        pass: EMAIL_PASS,
      },
      // Optional: Increase connection timeout if experiencing issues
      // pool: true, // Use a pool of connections
      // maxConnections: 5,
      // maxMessages: 100,
      // rateLimit: 10 // send 10 emails per second
    });
    logger.info('Nodemailer transporter initialized.');
  }
  return transporter;
};


const sendEmail = async ({ to, subject, htmlContent }) => {
  logger.info(`Attempting to send email to: ${to}, Subject: ${subject}`);

  const mailTransporter = createTransporter();
  if (!mailTransporter) {
    logger.error('Email transporter not available. Skipping actual email send.');
    console.log(`--- SIMULATED EMAIL CONTENT (EMAIL SERVICE NOT CONFIGURED) ---`);
    console.log(`TO: ${to}`);
    console.log(`SUBJECT: ${subject}`);
    console.log(`BODY:\n${htmlContent}`);
    console.log(`------------------------------------------------------------`);
    return false; // Indicate simulated failure or unconfigured state
  }

  try {
    const info = await mailTransporter.sendMail({
      from: `"Knowledge Hub IAM" <${EMAIL_USER}>`, // Display name and your sender email
      to,
      subject,
      html: htmlContent,
    });
    logger.info(`Email sent successfully to ${to}. Message ID: ${info.messageId}`);
    console.log(`Actual email sent to ${to}. Message ID: ${info.messageId}`);
    return true;
  } catch (error) {
    logger.error(`Failed to send email to ${to}. Error: ${error.message}`, { to, subject, error: error.stack });
    console.error(`Error sending email: ${error.message}`);
    // Log more specific Nodemailer errors if available
    if (error.code === 'EAUTH') {
        console.error('Authentication error with email service. Check EMAIL_USER and EMAIL_PASS.');
    } else if (error.code === 'EENVELOPE') {
        console.error('Email envelope error. Check recipient email address format.');
    }
    return false;
  }
};

module.exports = { sendEmail };