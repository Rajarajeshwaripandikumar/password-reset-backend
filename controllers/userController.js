// backend/controllers/userController.js
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import validator from "validator"; // npm i validator
import User from "../models/User.js";

const JWT_SECRET = process.env.JWT_SECRET;
const SALT_ROUNDS = parseInt(process.env.SALT_ROUNDS || "12", 10);
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || "1h"; // e.g. "1h", "7d"

// Fail-fast if secret missing (prevents insecure fallback)
if (!JWT_SECRET) {
  throw new Error(
    "Missing JWT_SECRET environment variable. Set JWT_SECRET in your .env or platform config."
  );
}

// Helper to build token
function buildToken(user) {
  const payload = { sub: user._id.toString(), email: user.email };
  return jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
}

/**
 * POST /api/auth/register
 * Body: { email, password }
 */
export async function registerUser(req, res) {
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
    console.error("registerUser error:", err && err.message ? err.message : err);
    return res.status(500).json({ message: "Server error" });
  }
}

/**
 * POST /api/auth/login
 * Body: { email, password }
 */
export async function loginUser(req, res) {
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

    // Option A: set HttpOnly cookie (recommended for browser-based clients)
    // uncomment and configure cookie options if you want cookie-based auth:
    // res.cookie('token', token, {
    //   httpOnly: true,
    //   secure: process.env.NODE_ENV === 'production',
    //   sameSite: 'lax',
    //   maxAge: 1000 * 60 * 60 // e.g. 1 hour
    // });
    // return res.status(200).json({ message: 'Login successful' });

    // Option B: return token in response body (API clients)
    return res.status(200).json({
      message: "Login successful",
      token,
      user: { id: user._id, email: user.email }
    });
  } catch (err) {
    console.error("loginUser error:", err && err.message ? err.message : err);
    return res.status(500).json({ message: "Server error" });
  }
}
