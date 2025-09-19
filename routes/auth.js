// backend/routes/auth.js
import express from "express";
import { body, validationResult } from "express-validator";

import {
  forgotPassword,
  validateResetToken,
  resetPassword,
} from "../controllers/authController.js";
import { registerUser, loginUser } from "../controllers/userController.js";

const router = express.Router();

// Middleware to handle validation results
const validate = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  next();
};

/**
 * Auth: Register & Login
 */
router.post(
  "/register",
  [
    body("email").isEmail().withMessage("Invalid email format"),
    body("password")
      .isLength({ min: 6 })
      .withMessage("Password must be at least 6 characters long"),
  ],
  validate,
  registerUser
);

router.post(
  "/login",
  [
    body("email").isEmail().withMessage("Invalid email format"),
    body("password").notEmpty().withMessage("Password is required"),
  ],
  validate,
  loginUser
);

/**
 * Password reset routes
 *
 * Note: we register BOTH `/forgot` and `/forgot-password` (and same for reset)
 * so older clients/tests that call either will work.
 */

// primary / modern route
router.post("/forgot-password", forgotPassword);
// alias for older tests / external clients
router.post("/forgot", forgotPassword);

// validate token (GET)
router.get("/reset-password/:token", validateResetToken);
router.get("/reset/:token", validateResetToken);

// submit new password (POST)
router.post("/reset-password/:token", resetPassword);
router.post("/reset/:token", resetPassword);

export default router;
