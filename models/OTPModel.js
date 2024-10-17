const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const { mailSender } = require("../mailer");

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
    expires: 60 * 5, // 5 minutes expiration
  },
});

// Hash and send OTP on save (new or updated)
otpSchema.pre("save", async function (next) {
  // Hash the OTP if it's new or modified (updated)
  if (this.isModified("otp")) {
    const salt = await bcrypt.genSalt(10);

    // Send the verification email before hashing the OTP
    await sendVerificationEmail(this.email, this.otp, this.otp_type);

    // Hash the OTP
    this.otp = await bcrypt.hash(this.otp, salt);
  }
  next();
});

// Method to compare input OTP with hashed OTP
otpSchema.methods.compareOTP = async function (otp, hashedOTP) {
  return await bcrypt.compare(otp, hashedOTP);
};

// Function to send email
async function sendVerificationEmail(email, otp, otpType) {
  try {
    await mailSender(email, otp, otpType);
  } catch (error) {
    console.log(error);
    throw new Error("Error sending email");
  }
}

const OTP = new mongoose.model("OTP", otpSchema);
module.exports = OTP;
