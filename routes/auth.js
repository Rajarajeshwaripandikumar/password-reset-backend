const express = require('express');
const { body, validationResult } = require('express-validator');
const router = express.Router();

const {
  forgotPassword,
  validateResetToken,
  resetPassword
} = require('../controllers/authController');

const { registerUser, loginUser } = require('../controllers/userController');

// Middleware to handle validation results
const validate = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    // return all validation errors
    return res.status(400).json({ errors: errors.array() });
  }
  next();
};

// ✅ Register & Login with validation
router.post(
  '/register',
  [
    body('email').isEmail().withMessage('Invalid email format'),
    body('password')
      .isLength({ min: 6 })
      .withMessage('Password must be at least 6 characters long')
  ],
  validate,
  registerUser
);

router.post(
  '/login',
  [
    body('email').isEmail().withMessage('Invalid email format'),
    body('password').notEmpty().withMessage('Password is required')
  ],
  validate,
  loginUser
);

// ✅ Password Reset
router.post('/forgot-password', forgotPassword);
router.get('/reset-password/:token', validateResetToken);
router.post('/reset-password/:token', resetPassword);

module.exports = router;
