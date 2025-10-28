// backend/controllers/authController.js
import crypto from "crypto";
import bcrypt from "bcrypt";
import User from "../models/User.js";           // make sure the model file uses an export compatible with ESM
import sendEmail from "../utils/sendEmail.js"; // likewise ensure utils export is compatible

const TOKEN_EXPIRES_MINUTES = parseInt(process.env.TOKEN_EXPIRES_MINUTES || "15", 10);
const TOKEN_EXPIRES_MS = TOKEN_EXPIRES_MINUTES * 60 * 1000;
const BCRYPT_SALT_ROUNDS = parseInt(process.env.BCRYPT_SALT_ROUNDS || "10", 10);
const REVEAL_ACCOUNT_EXISTENCE = process.env.REVEAL_ACCOUNT_EXISTENCE === "true";

const EMAIL_BASE_URL =
  process.env.EMAIL_BASE_URL ||
  process.env.CLIENT_URL ||
  (process.env.FRONTEND_URLS ? process.env.FRONTEND_URLS.split(",")[0].trim() : null) ||
  (process.env.NODE_ENV === "production"
    ? "https://password-reset-backend-nn1u.onrender.com"
    : "http://localhost:3000");

function makeResetUrl(token) {
  return `${EMAIL_BASE_URL.replace(/\/$/, "")}/reset-password/${token}`;
}

function hashToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

export const forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ message: "Email is required" });

    const normalized = email.toLowerCase().trim();
    const user = await User.findOne({ email: normalized });

    if (!user) {
      if (REVEAL_ACCOUNT_EXISTENCE) {
        return res.status(404).json({ message: "No account with that email exists" });
      } else {
        console.info(`Password reset requested for non-existent email: ${normalized}`);
        return res.status(200).json({ message: "Password reset link has been sent if the account exists" });
      }
    }

    const token = crypto.randomBytes(32).toString("hex");
    const hashed = hashToken(token);

    user.resetPasswordToken = hashed;
    user.resetPasswordExpires = Date.now() + TOKEN_EXPIRES_MS;
    await user.save();

    const resetUrl = makeResetUrl(token);
    if (process.env.NODE_ENV !== "production") console.debug("DEBUG resetUrl:", resetUrl);

    try {
      await sendEmail({
        to: user.email,
        subject: "Password Reset Request",
        html: `
          <p>You requested a password reset. Click the link below to reset your password (valid for ${TOKEN_EXPIRES_MINUTES} minutes):</p>
          <p><a href="${resetUrl}">${resetUrl}</a></p>
          <p>If you didn't request this, please ignore this email.</p>
        `,
      });
    } catch (emailErr) {
      console.error("Failed to send reset email (continuing):", emailErr);
    }

    return res.status(200).json({ message: "Password reset link has been sent if the account exists" });
  } catch (err) {
    console.error("ERROR in forgotPassword:", err);
    return res.status(500).json({ message: "Server error" });
  }
};

export const validateResetToken = async (req, res) => {
  try {
    const { token } = req.params;
    if (!token) return res.status(400).json({ message: "Invalid request" });

    const hashed = hashToken(token);
    const user = await User.findOne({
      resetPasswordToken: hashed,
      resetPasswordExpires: { $gt: Date.now() },
    });

    if (!user) return res.status(400).json({ message: "Invalid or expired token" });

    return res.status(200).json({ message: "Token valid" });
  } catch (err) {
    console.error("ERROR in validateResetToken:", err);
    return res.status(500).json({ message: "Server error" });
  }
};

export const resetPassword = async (req, res) => {
  try {
    const { token } = req.params;
    const { password } = req.body;

    if (!token || !password) return res.status(400).json({ message: "Invalid request" });
    if (typeof password !== "string" || password.length < 6)
      return res.status(400).json({ message: "Password must be >= 6 chars" });

    const hashedToken = hashToken(token);
    const user = await User.findOne({
      resetPasswordToken: hashedToken,
      resetPasswordExpires: { $gt: Date.now() },
    });

    if (!user) return res.status(400).json({ message: "Invalid or expired token" });

    const hashedPassword = await bcrypt.hash(password, BCRYPT_SALT_ROUNDS);
    user.password = hashedPassword;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();

    try {
      await sendEmail({
        to: user.email,
        subject: "Your password was changed",
        html: `<p>Your password was successfully changed. If you did not perform this action, contact support immediately.</p>`,
      });
    } catch (emailErr) {
      console.error("Failed to send confirmation email:", emailErr);
    }

    return res.status(200).json({ message: "Password has been reset" });
  } catch (err) {
    console.error("ERROR in resetPassword:", err);
    return res.status(500).json({ message: "Server error" });
  }
};
