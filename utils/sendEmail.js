// backend/utils/sendEmail.js

/* --------------------------------------------------------
   Email Utility (Render-Compatible)
   Uses Nodemailer + SendGrid Transport
   --------------------------------------------------------
   Works with CommonJS (`require`) and your current
   package.json (no need for ES module conversion).
   -------------------------------------------------------- */

const nodemailer = require("nodemailer");
const sgTransport = require("nodemailer-sendgrid-transport");

// --------------------------------------------------------
// 1️⃣ Configure the SendGrid transporter
// --------------------------------------------------------
const transporter = nodemailer.createTransport(
  sgTransport({
    auth: {
      api_key: process.env.SENDGRID_API_KEY, // From Render env
    },
  })
);

// --------------------------------------------------------
// 2️⃣ Send email wrapper function
// --------------------------------------------------------
async function sendEmail({ to, subject, html, text }) {
  // Build the message
  const message = {
    from: process.env.FROM_EMAIL || "no-reply@yourdomain.com",
    to,
    subject,
    text: text || undefined,
    html: html || undefined,
  };

  try {
    // Send the email
    const info = await transporter.sendMail(message);

    // Log success for Render console visibility
    console.log("✅ Email sent successfully:");
    console.log("   ➤ To:", to);
    console.log("   ➤ Subject:", subject);
    console.log("   ➤ Message ID:", info && info.messageId);

    return info;
  } catch (err) {
    // Log full error details for debugging
    console.error("❌ SendGrid email error:", err?.response || err.message);
    throw err;
  }
}

// --------------------------------------------------------
// 3️⃣ Export function
// --------------------------------------------------------
module.exports = sendEmail;
