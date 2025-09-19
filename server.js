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

// When behind a proxy (Render, Heroku, nginx) this helps req.ip and rate-limiters
app.set("trust proxy", true);

// JSON body parser
app.use(express.json());

// security headers (lightweight)
app.use(helmet());

// --- CORS Setup ---

const rawFrontends =
  process.env.CLIENT_URL ||
  process.env.FRONTEND_URLS ||
  process.env.FRONTEND_URL ||
  (process.env.NODE_ENV === "production"
    ? "https://password-reset-7.netlify.app" // ✅  Netlify frontend
    : "http://localhost:3000");              // ✅ dev fallback

const ALLOWED_ORIGINS = String(rawFrontends)
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

const corsOptions = {
  origin: function (origin, callback) {
    if (!origin) return callback(null, true); // allow Postman / curl
    if (ALLOWED_ORIGINS.includes(origin)) {
      return callback(null, true);
    }
    console.warn(`❌ CORS blocked: ${origin}`);
    return callback(null, false); // no headers if origin not allowed
  },
  credentials: true, // enable if you send cookies
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization", "Accept"],
  optionsSuccessStatus: 204,
};

app.use(cors(corsOptions));
app.options("*", cors(corsOptions)); // preflight handler

// --- Health check ---
app.get("/health", (req, res) => {
  res.json({
    ok: true,
    time: Date.now(),
    clientUrl: process.env.CLIENT_URL || null,
    allowedOrigins: ALLOWED_ORIGINS,
  });
});
const FRONTEND_URL =
  process.env.CLIENT_URL ||
  (process.env.FRONTEND_URLS ? process.env.FRONTEND_URLS.split(',')[0].trim() : 'https://password-reset-7.netlify.app');

app.get('/reset-password/:token', (req, res) => {
  const token = req.params.token;
  res.redirect(`${FRONTEND_URL.replace(/\/$/, '')}/reset-password/${encodeURIComponent(token)}`);
});
// --- Routes ---
app.use("/api/auth", authRoutes);

// --- Favicon handler (optional) ---
app.use(
  "/favicon.ico",
  express.static(path.join(process.cwd(), "public", "favicon.ico"))
);

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

// --- Graceful shutdown ---
process.on("SIGINT", () => {
  console.log("SIGINT received: closing server");
  mongoose.disconnect().then(() => process.exit(0));
});
