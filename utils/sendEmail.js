// backend/utils/sendEmail.js
const nodemailer = require('nodemailer');

async function sendEmail({ to, subject, html, text }) {
  const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: parseInt(process.env.SMTP_PORT || '587', 10),
    secure: false, // true for 465, false for 587
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS
    }
  });

  // verify connection configuration (optional - useful for debugging)
  try {
    await transporter.verify();
    console.log('SMTP connection OK');
  } catch (err) {
    console.error('SMTP connection error:', err);
    // rethrow so caller can handle/log if needed
    throw err;
  }

  const message = {
    from: process.env.FROM_EMAIL,
    to,
    subject,
    text: text || undefined,
    html: html || undefined
  };

  const info = await transporter.sendMail(message);
  console.log('Email sent:', info.messageId);
  return info;
}

module.exports = sendEmail;
