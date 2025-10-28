// backend/utils/sendEmail.js
import nodemailer from "nodemailer";
import sgTransport from "nodemailer-sendgrid-transport";

/* --------------------------------------------------------
   Email Utility (Render-Compatible)
   Uses Nodemailer + SendGrid Transport (ESM version)
   -------------------------------------------------------- */

const transporter = nodemailer.createTransport(
  sgTransport({
    auth: {
      api_key: process.env.SENDGRID_API_KEY, // from Render env
    },
  })
);

export default async function sendEmail({ to, subject, html, text }) {
  const message = {
    from: process.env.FROM_EMAIL || "no-reply@yourdomain.com",
    to,
    subject,
    text: text || undefined,
    html: html || undefined,
  };

  try {
    const info = await transporter.sendMail(message);
    console.log("✅ Email sent successfully:");
    console.log("   ➤ To:", to);
    console.log("   ➤ Subject:", subject);
    console.log("   ➤ Message ID:", info && info.messageId);
    return info;
  } catch (err) {
    console.error("❌ SendGrid email error:", err?.response || err.message);
    throw err;
  }
}
