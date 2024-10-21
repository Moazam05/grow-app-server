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
      unique: true,
      sparse: true, // Allow null values without causing duplicates
      validate: [
        {
          validator: function (v) {
            return v == null || validator.isMobilePhone(v);
          },
          message: "Please provide a valid phone number",
        },
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
  if (!this.isModified("password")) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

// instance method for password comparison
userSchema.methods.comparePassword = async function (candidatePassword) {
  const isMatch = await bcrypt.compare(candidatePassword, this.password);

  if (!isMatch) {
    this.wrong_password_attempts += 1;
    if (this.wrong_password_attempts >= 3) {
      this.blocked_until_password = Date.now() + 3 * 60 * 1000; // 3 minutes
    }
  } else {
    this.wrong_password_attempts = 0;
  }

  await this.save();
  return isMatch;
};

// instance method for pin comparison
userSchema.methods.comparePin = async function (candidatePin) {
  const isMatch = await bcrypt.compare(candidatePin, this.login_pin);

  if (!isMatch) {
    this.wrong_pin_attempts += 1;
    if (this.wrong_pin_attempts >= 3) {
      this.blocked_until_pin = Date.now() + 3 * 60 * 1000; // 3 minutes
    }
  } else {
    this.wrong_pin_attempts = 0;
  }

  await this.save();
  return isMatch;
};

const User = new mongoose.model("User", userSchema);
module.exports = User;
