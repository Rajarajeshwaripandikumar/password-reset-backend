// backend/controllers/authController.js
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const User = require('../models/User');
const sendEmail = require('../utils/sendEmail');

function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

// Forgot Password
exports.forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ message: 'Email is required' });

    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) {
      // explicit 404 for dev/testing
      return res.status(404).json({ message: 'No account with that email exists' });
    }

    const token = crypto.randomBytes(32).toString('hex');
    const hashed = hashToken(token);

    user.resetPasswordToken = hashed;
    user.resetPasswordExpires = Date.now() + (parseInt(process.env.TOKEN_EXPIRES_MINUTES || '15', 10) * 60 * 1000);
    await user.save();

    const resetUrl = `${process.env.CLIENT_URL || 'https://password-reset-backend-nn1u.onrender.com'}/reset-password/${token}`;
    console.log('DEBUG resetUrl:', resetUrl);

    // send reset email
    try {
      await sendEmail({
        to: user.email,
        subject: 'Password Reset Request',
        html: `
          <p>You requested a password reset. Click the link below to reset your password (valid for ${process.env.TOKEN_EXPIRES_MINUTES || 15} minutes):</p>
          <p><a href="${resetUrl}">${resetUrl}</a></p>
          <p>If you didn't request this, please ignore this email.</p>
        `
      });
    } catch (emailErr) {
      console.error('Failed to send reset email:', emailErr);
      // do not fail the endpoint because of email sending failure
    }

    return res.status(200).json({ message: 'Password reset link has been sent' });
  } catch (err) {
    console.error('ERROR in forgotPassword:', err);
    return res.status(500).json({ message: 'Server error' });
  }
};

// Validate Reset Token
exports.validateResetToken = async (req, res) => {
  try {
    const { token } = req.params;
    if (!token) return res.status(400).json({ message: 'Invalid request' });

    const hashed = hashToken(token);
    const user = await User.findOne({
      resetPasswordToken: hashed,
      resetPasswordExpires: { $gt: Date.now() }
    });

    if (!user) return res.status(400).json({ message: 'Invalid or expired token' });

    return res.status(200).json({ message: 'Token valid' });
  } catch (err) {
    console.error('ERROR in validateResetToken:', err);
    return res.status(500).json({ message: 'Server error' });
  }
};

// Reset Password
exports.resetPassword = async (req, res) => {
  try {
    const { token } = req.params;
    const { password } = req.body;

    if (!token || !password) return res.status(400).json({ message: 'Invalid request' });
    if (typeof password !== 'string' || password.length < 6)
      return res.status(400).json({ message: 'Password must be >= 6 chars' });

    const hashedToken = hashToken(token);
    const user = await User.findOne({
      resetPasswordToken: hashedToken,
      resetPasswordExpires: { $gt: Date.now() }
    });

    if (!user) return res.status(400).json({ message: 'Invalid or expired token' });

    const hashedPassword = await bcrypt.hash(password, 10);
    user.password = hashedPassword;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();

    // send confirmation email (best-effort)
    try {
      await sendEmail({
        to: user.email,
        subject: 'Your password was changed',
        html: `<p>Your password was successfully changed. If you did not perform this action, contact support immediately.</p>`
      });
    } catch (emailErr) {
      console.error('Failed to send confirmation email:', emailErr);
    }

    return res.status(200).json({ message: 'Password has been reset' });
  } catch (err) {
    console.error('ERROR in resetPassword:', err);
    return res.status(500).json({ message: 'Server error' });
  }
};
