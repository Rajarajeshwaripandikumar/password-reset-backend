// controllers/authController.js
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const validator = require("validator"); // npm i validator
const User = require("../models/User");

const JWT_SECRET = process.env.JWT_SECRET;
const SALT_ROUNDS = parseInt(process.env.SALT_ROUNDS || "12", 10);
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || "1h"; // e.g. "1h", "7d"

// Fail-fast if secret missing (this file is required at startup)
if (!JWT_SECRET) {
  // throw so app crashes early in non-dev environments - prevents insecure fallback
  throw new Error("Missing JWT_SECRET environment variable. Set JWT_SECRET in your .env or platform config.");
}

// Helper to build token
function buildToken(user) {
  // minimal claims - avoid putting sensitive or excessive data
  const payload = { sub: user._id.toString(), email: user.email };
  return jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
}

// POST /api/auth/register
exports.registerUser = async (req, res) => {
  try {
    const { email = "", password = "" } = req.body;

    // Basic validation
    const emailClean = String(email).trim().toLowerCase();
    if (!validator.isEmail(emailClean)) {
      return res.status(400).json({ message: "Please provide a valid email address." });
    }
    if (typeof password !== "string" || password.length < 6) {
      return res.status(400).json({ message: "Password must be at least 6 characters." });
    }

    // Check for existing user
    const existing = await User.findOne({ email: emailClean }).lean();
    if (existing) {
      // Generic message to avoid user enumeration
      return res.status(400).json({ message: "Unable to register with provided credentials." });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

    const user = new User({ email: emailClean, password: hashedPassword });
    await user.save();

    return res.status(201).json({ message: "User registered successfully" });
  } catch (err) {
    // Log for server-side debugging, but don't return internal error details to clients
    console.error("registerUser error:", err && err.message ? err.message : err);
    return res.status(500).json({ message: "Server error" });
  }
};

// POST /api/auth/login
exports.loginUser = async (req, res) => {
  try {
    const { email = "", password = "" } = req.body;

    const emailClean = String(email).trim().toLowerCase();
    if (!validator.isEmail(emailClean) || typeof password !== "string") {
      return res.status(400).json({ message: "Email and password required" });
    }

    const user = await User.findOne({ email: emailClean });
    if (!user) {
      // generic message: don't reveal which side failed
      return res.status(400).json({ message: "Invalid credentials" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      // consider incrementing a failed-login counter here for lockout after N attempts
      return res.status(400).json({ message: "Invalid credentials" });
    }

    // Generate JWT token
    const token = buildToken(user);

    // Option A (recommended for browser apps): set HttpOnly secure cookie.
    // In production, set cookie options: secure: true (HTTPS), sameSite: 'Lax' or 'Strict' depending on CORS needs.
    // res.cookie('token', token, {
    //   httpOnly: true,
    //   secure: process.env.NODE_ENV === 'production',
    //   sameSite: 'lax',
    //   maxAge: 1000 * 60 * 60 // 1 hour in ms
    // });
    // return res.status(200).json({ message: "Login successful" });

    // Option B: return token in response body (still acceptable for many APIs but client must store securely)
    return res.status(200).json({
      message: "Login successful",
      token,
      // optionally return a minimal user profile
      user: { id: user._id, email: user.email },
    });
  } catch (err) {
    console.error("loginUser error:", err && err.message ? err.message : err);
    return res.status(500).json({ message: "Server error" });
  }
};
