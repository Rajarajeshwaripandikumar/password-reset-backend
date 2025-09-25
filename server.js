// backend/server.js
import express from "express";
import mongoose from "mongoose";
import dotenv from "dotenv";
import cors from "cors";
import path from "path";
import helmet from "helmet";
import authRoutes from "./routes/auth.js";

dotenv.config();
const app = express();

// trust proxy (if behind Render/Heroku/nginx)
app.set("trust proxy", true);

app.use(express.json());
app.use(helmet());

// -------- FRONTEND / ALLOWED ORIGINS --------
const rawFrontends =
  process.env.CLIENT_URL ||
  process.env.FRONTEND_URLS ||
  process.env.FRONTEND_URL ||
  (process.env.NODE_ENV === "production"
    ? "https://password-reset-7.netlify.app"
    : "http://localhost:3000");

const ALLOWED_ORIGINS = String(rawFrontends)
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

// debug env to allow everything temporarily (set to "true" only while debugging)
const DEBUG_ALLOW_ALL = String(process.env.DEBUG_CORS_ALLOW_ALL || "").toLowerCase() === "true";

/**
 * Check whether an origin is allowed:
 * - allow explicit ALLOWED_ORIGINS
 * - allow any netlify preview host under *.netlify.app
 */
function isOriginAllowed(origin) {
  if (!origin) return true; // allow Postman / curl (no Origin header)
  if (DEBUG_ALLOW_ALL) return true;
  if (ALLOWED_ORIGINS.includes(origin)) return true;
  try {
    const host = new URL(origin).hostname;
    if (host.endsWith(".netlify.app")) return true;
  } catch (err) {
    // invalid origin -> deny
  }
  return false;
}

// --- Manual preflight handler: always respond to OPTIONS with proper CORS headers if allowed
app.options("*", (req, res) => {
  const origin = req.headers.origin;
  // Allow non-browser tools (no Origin)
  if (!origin) return res.sendStatus(204);

  if (!isOriginAllowed(origin)) {
    console.warn(`❌ CORS preflight blocked: ${origin}`);
    // respond 403 so you can see the reason in server logs; browser will still block.
    return res.status(403).send("CORS origin not allowed");
  }

  // Allowed: set the required CORS headers for preflight
  res.setHeader("Access-Control-Allow-Origin", origin);
  res.setHeader("Vary", "Origin");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type,Authorization,Accept");
  // If you use cookies/auth across origins, set this to true
  res.setHeader("Access-Control-Allow-Credentials", "true");
  return res.sendStatus(204);
});

// --- cors middleware for non-preflight requests (reflect origin when allowed) ---
const corsOptions = {
  origin: function (origin, callback) {
    // allow curl/Postman (no origin)
    if (!origin) return callback(null, true);

    if (isOriginAllowed(origin)) {
      // callback(null, true) tells the cors package to reflect the origin back
      return callback(null, true);
    }

    // don't throw an Error here (that can lead to 500 without headers). Return false.
    console.warn(`❌ CORS blocked (normal request): ${origin}`);
    return callback(null, false);
  },
  credentials: true, // set true if you use cookies/credentials
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization", "Accept"],
  optionsSuccessStatus: 204,
};

app.use(cors(corsOptions));

// --- Health check ---
app.get("/health", (req, res) => {
  res.json({
    ok: true,
    time: Date.now(),
    clientUrl: process.env.CLIENT_URL || null,
    allowedOrigins: ALLOWED_ORIGINS,
    debugAllowAll: DEBUG_ALLOW_ALL,
  });
});

const FRONTEND_URL =
  process.env.CLIENT_URL ||
  (process.env.FRONTEND_URLS ? process.env.FRONTEND_URLS.split(",")[0].trim() : "https://password-reset-7.netlify.app");

app.get("/reset-password/:token", (req, res) => {
  const token = req.params.token;
  res.redirect(`${FRONTEND_URL.replace(/\/$/, "")}/reset-password/${encodeURIComponent(token)}`);
});

// --- Routes ---
app.use("/api/auth", authRoutes);

// favicon
app.use("/favicon.ico", express.static(path.join(process.cwd(), "public", "favicon.ico")));

// --- Start server after MongoDB connection ---
const PORT = process.env.PORT || 5000;

if (!process.env.MONGO_URI) {
  console.error("❌ MONGO_URI is not set. Set it in your environment variables.");
  process.exit(1);
}

mongoose
  .connect(process.env.MONGO_URI)
  .then(() => {
    console.log("✅ Connected to MongoDB");
    app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
  })
  .catch((err) => {
    console.error("❌ MongoDB connection error:", err);
    process.exit(1);
  });

// graceful shutdown
process.on("SIGINT", () => {
  console.log("SIGINT received: closing server");
  mongoose.disconnect().then(() => process.exit(0));
});
