// backend/utils/sendEmail.js
const nodemailer = require("nodemailer");
const sgTransport = require("nodemailer-sendgrid-transport");

// -----------------------------
// 1️⃣ Configure the transporter
// -----------------------------
const transporter = nodemailer.createTransport(
  sgTransport({
    auth: { api_key: process.env.SENDGRID_API_KEY },
  })
);

// -----------------------------
// 2️⃣ Send email wrapper
// -----------------------------
async function sendEmail({ to, subject, html, text }) {
  const message = {
    from: process.env.FROM_EMAIL || "no-reply@yourdomain.com",
    to,
    subject,
    text: text || undefined,
    html: html || undefined,
  };

  try {
    const info = await transporter.sendMail(message);
    console.log("✅ Email sent:", info && info.messageId);
    return info;
  } catch (err) {
    console.error("❌ SendGrid email error:", err);
    throw err;
  }
}

module.exports = sendEmail;
