require("dotenv").config();
const jwt = require("jsonwebtoken");
const { promisify } = require("util");
const bcrypt = require("bcryptjs");
// Custom Imports
const User = require("../models/userModel");
const catchAsync = require("../utils/catchAsync");
const AppError = require("../utils/appError");
const { generateOTP } = require("../mailer");
const OTP = require("../models/OTPModel");

const signToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN,
  });
};

const createSendToken = (user, statusCode, res) => {
  const token = signToken(user._id);

  // Remove password from output
  user.password = undefined;

  res.status(statusCode).json({
    status: "success",
    token,
    data: {
      user,
    },
  });
};

// todo: LOGIN USER
exports.login = catchAsync(async (req, res, next) => {
  const { email, password } = req.body;

  // 1) Check if email and password exist
  if (!email || !password) {
    return next(new AppError("Please provide email and password", 400));
  }

  // 2) Check if user exists && password is exist
  const user = await User.findOne({ email });
  if (!user) {
    return next(new AppError("Incorrect email or password", 401));
  }

  const correct = await user.correctPassword(password, user.password);
  if (!correct) {
    return next(new AppError("Incorrect email or password", 401));
  }

  // 3) If everything ok, send token to client
  createSendToken(user, 200, res);
});

// todo: CHECK EMAIL
exports.checkEmail = catchAsync(async (req, res, next) => {
  const { email } = req.body;

  if (!email) {
    return next(new AppError("Please provide email", 400));
  }

  let user = await User.findOne({
    email,
  });

  if (!user) {
    user = await User.create({
      email,
    });
  }

  if (!user.email_verified || !user.password) {
    // Generate a new OTP
    const otp = await generateOTP();

    // Check if an OTP for this email already exists
    let existingOtp = await OTP.findOne({ email, otp_type: "email" });

    if (existingOtp) {
      // Update the existing OTP and reset expiration time
      existingOtp.otp = otp; // New OTP will be hashed and email will be sent in the `pre` hook
      existingOtp.createdAt = Date.now(); // Reset the expiration timer
      await existingOtp.save();
    } else {
      // Create a new OTP entry if none exists
      await OTP.create({ email, otp, otp_type: "email" });
    }
  }

  res.status(200).json({
    status: "success",
    data: {
      email_verified: user.email_verified,
      phone_verified: user.phone_verified,
    },
  });
});

exports.verifyOTP = catchAsync(async (req, res, next) => {
  const { email, otp, otp_type, data } = req.body;

  if (!email || !otp || !otp_type) {
    return next(new AppError("Please provide email, otp and otp_type", 400));
  }

  const otpDoc = await OTP.findOne({
    email,
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
      await User.findOneAndUpdate(
        {
          email,
        },
        {
          login_pin: data,
        }
      );
      break;
    case "reset_password":
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

exports.setPassword = catchAsync(async (req, res, next) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return next(new AppError("Please provide email and password", 400));
  }

  const user = await User.findOne({ email });
  if (!user) {
    return next(new AppError("User not found", 404));
  }

  const hashedPassword = await bcrypt.hash(password, 12);

  await User.findOneAndUpdate(
    {
      email,
    },
    {
      password: hashedPassword,
    }
  );

  res.status(200).json({
    status: "success",
    message: "Password set successfully",
  });
});

// todo: PROTECT ROUTES ** MIDDLEWARE **
exports.protect = catchAsync(async (req, res, next) => {
  // 1) Getting token and check of it's there
  let token;
  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith("Bearer")
  ) {
    token = req.headers.authorization.split(" ")[1];
  }

  if (!token) {
    return next(
      new AppError("You are not logged in! Please log in to get access.", 401)
    );
  }

  // 2) Verification token
  const decode = await promisify(jwt.verify)(token, process.env.JWT_SECRET);

  // 3) Check if user still exists
  const freshUser = await User.findById(decode.id);
  if (!freshUser) {
    return next(
      new AppError(
        "The user belonging to this token does no longer exist.",
        401
      )
    );
  }

  // GRANT ACCESS TO PROTECTED ROUTE
  req.user = freshUser;
  next();
});
