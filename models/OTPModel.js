const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");

const otpSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
  },
  otp_type: {
    type: String,
    required: true,
    enum: ["email", "phone", "reset_password", "reset_pin"],
  },
  otp: {
    type: String,
    required: true,
  },
  createdAt: {
    type: Date,
    default: Date.now,
    expires: 60 * 5,
  },
});

otpSchema.pre("save", async function (next) {
  if (this.isNew) {
    const salt = await bcrypt.genSalt(10);
    // send mail
    this.otp = await bcrypt.hash(this.otp, salt);
  }
  next();
});

otpSchema.methods.compareOTP = async function (otp, hashedOTP) {
  return await bcrypt.compare(otp, hashedOTP);
};

async function sendVerificationEmail(email, otp, otpType) {
  try {
  } catch (error) {
    console.log(error);
    throw new Error("Error sending email");
  }
}

const OTP = new mongoose.model("OTP", otpSchema);
module.exports = OTP;
