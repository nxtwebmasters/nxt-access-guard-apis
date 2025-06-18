// utils/emailService.js
const { logger } = require('./logger');
require('dotenv').config();

const sendEmail = async ({ to, subject, htmlContent }) => {
  logger.info(`Sending email to: ${to}, Subject: ${subject}`);
  // In a real application, integrate with an email service like SendGrid, Nodemailer, Mailgun, etc.
  /*
  const nodemailer = require('nodemailer');
  let transporter = nodemailer.createTransport({
    service: 'gmail', // or other service
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
  });
  await transporter.sendMail({
    from: '"IAM Service" <no-reply@yourdomain.com>',
    to,
    subject,
    html: htmlContent,
  });
  */
  console.log(`--- SIMULATED EMAIL CONTENT ---`);
  console.log(`TO: ${to}`);
  console.log(`SUBJECT: ${subject}`);
  console.log(`BODY:\n${htmlContent}`);
  console.log(`------------------------------`);
  return true; // Simulate success
};

module.exports = { sendEmail };