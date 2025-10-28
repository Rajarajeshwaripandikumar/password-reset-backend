// backend/models/User.js
import mongoose from 'mongoose';

const { Schema, model } = mongoose;

const userSchema = new Schema(
  {
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
    },
    password: {
      type: String,
      required: true,
    },
    // password reset fields used by your controller
    resetPasswordToken: {
      type: String,
      default: undefined,
    },
    resetPasswordExpires: {
      type: Date,
      default: undefined,
    },

    // add any other fields you need (name, roles, etc.)
    name: {
      type: String,
      default: '',
      trim: true,
    },
  },
  { timestamps: true }
);

export default model('User', userSchema);
