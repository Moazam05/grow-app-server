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
      maxLength: 20,
    },
    login_pin: {
      type: String,
      minlength: 4,
      maxLength: 4,
    },
    phone_number: {
      type: String,
      validate: [
        validator.isMobilePhone,
        "Please provide a valid phone number",
      ],
    },
    address: {
      type: String,
    },
    date_of_birth: {
      type: Date,
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
userSchema.methods.correctPassword = async function (
  candidatePassword,
  userPassword
) {
  return await bcrypt.compare(candidatePassword, userPassword);
};

// create access token
userSchema.methods.createAccessToken = function () {
  return jwt.sign(
    { userId: this._id, name: this.name },
    process.env.JWT_SECRET,
    {
      expiresIn: process.env.ACCESS_TOKEN_EXPIRY,
    }
  );
};

// create refresh token
userSchema.methods.createRefreshToken = function () {
  return jwt.sign({ userId: this._id }, process.env.REFRESH_TOKEN_SECRET, {
    expiresIn: process.env.REFRESH_TOKEN_EXPIRY,
  });
};

const User = new mongoose.model("User", userSchema);
module.exports = User;
