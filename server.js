// backend/server.js (improved)
import express from "express";
import mongoose from "mongoose";
import dotenv from "dotenv";
import cors from "cors";
import authRoutes from "./routes/auth.js";

dotenv.config();
const app = express();

// Optional security (uncomment/install if desired)
// import helmet from "helmet";
// import rateLimit from "express-rate-limit";
// app.use(helmet());
// const limiter = rateLimit({ windowMs: 60_000, max: 100 });
// app.use(limiter);

app.use(express.json());

// Allow multiple origins via comma-separated env var, or single FRONTEND_URL
// Example: FRONTEND_URLS="http://localhost:3000,https://password-reset-yn39.onrender.com/"
const rawFrontends = process.env.FRONTEND_URLS || process.env.FRONTEND_URL || "http://localhost:3000";
const ALLOWED_ORIGINS = rawFrontends.split(",").map(s => s.trim()).filter(Boolean);

const corsOptions = {
  origin: function (origin, callback) {
    // Allow no-origin (e.g. server-to-server or Postman) by returning true
    if (!origin) return callback(null, true);
    if (ALLOWED_ORIGINS.indexOf(origin) !== -1) {
      return callback(null, true);
    } else {
      return callback(new Error("CORS_NOT_ALLOWED_BY_SERVER"));
    }
  },
  credentials: true,
  methods: ["GET","POST","PUT","DELETE","OPTIONS"],
  allowedHeaders: ["Content-Type","Authorization","Accept"]
};

// apply CORS to all routes
app.use(cors(corsOptions));

// Simple health route for quick testing
app.get("/health", (req, res) => res.json({ ok: true, time: Date.now(), allowedOrigins: ALLOWED_ORIGINS }));

// Routes
app.use("/api/auth", authRoutes);

const PORT = process.env.PORT || 5000;

if (!process.env.MONGO_URI) {
  console.error("❌ MONGO_URI is not set. Set it in your environment variables.");
  process.exit(1);
}

mongoose
  .connect(process.env.MONGO_URI)
  .then(() => {
    console.log("✅ Connected to MongoDB");
    app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
  })
  .catch((err) => {
    console.error("❌ MongoDB connection error:");
    console.error(err);
    process.exit(1);
  });

// graceful shutdown (nice to have)
process.on("SIGINT", () => {
  console.log("SIGINT received: closing server");
  mongoose.disconnect().then(() => process.exit(0));
});
