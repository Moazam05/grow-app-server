const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const validator = require("validator");
const jwt = require("jsonwebtoken");

const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      maxLength: 50,
      minlength: 3,
    },
    email: {
      type: String,
      unique: true,
      lowercase: true,
      required: [true, "Please provide your email"],
      validate: [validator.isEmail, "Please provide a valid email"],
    },
    password: {
      type: String,
      minlength: 6,
    },
    login_pin: {
      type: String,
      minlength: 4,
    },
    phone_number: {
      type: String,
      validate: [
        validator.isMobilePhone,
        "Please provide a valid phone number",
      ],
    },
    gender: {
      type: String,
      enum: ["Male", "Female", "Other"],
    },
    date_of_birth: {
      type: Date,
    },
    biometricKey: {
      type: String,
    },
    email_verified: {
      type: Boolean,
      default: false,
    },
    phone_verified: {
      type: Boolean,
      default: false,
    },
    bank_amount: {
      type: Number,
      default: 0,
    },
    wrong_pin_attempts: {
      type: Number,
      default: 0,
    },
    blocked_until_pin: {
      type: Date,
      default: null,
    },
    wrong_password_attempts: {
      type: Number,
      default: 0,
    },
    blocked_until_password: {
      type: Date,
      default: null,
    },
  },
  {
    timestamps: true,
  }
);

// Password Hashing
userSchema.pre("save", async function (next) {
  if (this?.password) {
    // Only hash the password if it is new or has been modified
    if (!this.isModified("password")) return next();

    // Hash the password with cost of 12
    this.password = await bcrypt.hash(this.password, 12);

    next();
  }
});

// instance method
userSchema.methods.correctPassword = async function (candidatePassword) {
  const isMatch = await bcrypt.compare(candidatePassword, this.password);

  if (!isMatch) {
    this.wrong_password_attempts += 1;
    if (this.wrong_password_attempts >= 3) {
      this.blocked_until_password = Date.now() + 30 * 60 * 1000; // 30 minutes
    }
  } else {
    this.wrong_password_attempts = 0;
  }

  await this.save();
  return isMatch;
};

const User = new mongoose.model("User", userSchema);
module.exports = User;
