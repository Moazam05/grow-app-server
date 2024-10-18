const catchAsync = require("../utils/catchAsync");
const AppError = require("../utils/appError");
const { generateOTP } = require("../mailer");
const OTP = require("../models/OTPModel");
const User = require("../models/userModel");
const bcrypt = require("bcryptjs");

exports.verifyOTP = catchAsync(async (req, res, next) => {
  const { email, otp, otp_type, data } = req.body;

  if (!email || !otp || !otp_type) {
    return next(new AppError("Please provide email, otp and otp_type", 400));
  }

  const otpDoc = await OTP.findOne({
    email,
    otp_type,
  });

  if (!otpDoc) {
    return next(new AppError("Email not found", 400));
  }

  const isVerified = await otpDoc.compareOTP(otp, otpDoc.otp);

  if (!isVerified) {
    return next(new AppError("Invalid OTP", 400));
  }

  switch (otp_type) {
    case "phone":
      await User.findOneAndUpdate(
        {
          email,
        },
        {
          phone_number: data,
          phone_verified: true,
        }
      );
      break;
    case "email":
      await User.findOneAndUpdate(
        {
          email,
        },
        {
          email_verified: true,
        }
      );
      break;
    case "reset_pin":
      if (!data) {
        return next(new AppError("Please provide login pin", 400));
      }

      if (data.length !== 4) {
        return next(new AppError("Please provide 4 digit pin", 400));
      }
      const hashedPin = await bcrypt.hash(data, 12);

      await User.findOneAndUpdate(
        {
          email,
        },
        {
          login_pin: hashedPin,
        }
      );
      break;
    case "reset_password":
      if (!data) {
        return next(new AppError("Please provide password", 400));
      }
      const hashedPassword = await bcrypt.hash(data, 12);
      await User.findOneAndUpdate(
        {
          email,
        },
        {
          password: hashedPassword,
        }
      );
      break;
    default:
      throw new Error("Invalid OTP type");
  }

  res.status(200).json({
    status: "success",
    message: "OTP verified successfully",
  });
});

exports.sendOTP = catchAsync(async (req, res, next) => {
  const { email, otp_type } = req.body;

  if (!email || !otp_type) {
    return next(new AppError("Please provide email and otp_type", 400));
  }

  const otp = await generateOTP();

  const user = await User.findOne({
    email,
  });

  if (otp_type === "phone" && user.phone_number) {
    return next(new AppError("Phone number already exist", 400));
  }

  let existingOtp = await OTP.findOne({ email, otp_type });

  if (existingOtp) {
    // Update the existing OTP and reset expiration time
    existingOtp.otp = otp; // New OTP will be hashed and email will be sent in the `pre` hook
    existingOtp.createdAt = Date.now(); // Reset the expiration timer
    await existingOtp.save();
  } else {
    // Create a new OTP entry if none exists
    await OTP.create({ email, otp, otp_type });
  }

  res.status(200).json({
    status: "success",
    message: "OTP sent successfully",
  });
});
