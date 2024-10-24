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
  user.wrong_pin_attempts = undefined;
  user.blocked_until_pin = undefined;
  user.wrong_password_attempts = undefined;
  user.blocked_until_password = undefined;

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

  // 1) Validate input
  if (!email || !password) {
    return next(new AppError("Please provide email and password", 400));
  }

  // 2) Find user
  const user = await User.findOne({ email });
  if (!user) {
    return next(new AppError("User not found", 401));
  }

  const currentTime = Date.now();
  const blockedUntil = new Date(user.blocked_until_password).getTime();

  const isBlocked = blockedUntil > currentTime;

  if (isBlocked) {
    // Convert blockedUntil to a readable time (12-hour format)
    const unblockTime = new Date(blockedUntil).toLocaleTimeString("en-US", {
      hour: "2-digit",
      minute: "2-digit",
      hour12: true, // Ensures 12-hour format with AM/PM
    });

    return next(
      new AppError(
        `You are blocked from logging in. Please try again at ${unblockTime}.`,
        401
      )
    );
  }

  // 3) Verify password
  const correct = await user.comparePassword(password);
  if (!correct) {
    const attemptsLeft = 3 - user.wrong_password_attempts;
    if (attemptsLeft > 0) {
      return next(
        new AppError(
          `Incorrect Credentials. ${attemptsLeft} attempts left`,
          401
        )
      );
    } else {
      return next(new AppError(`Incorrect Credentials.`, 401));
    }
  }

  // 4) Send token
  createSendToken(user, 200, res);
});

// todo: LOGOUT USER
exports.logout = catchAsync(async (req, res, next) => {
  const user = req.user;

  // delete biometric key
  await User.findByIdAndUpdate(user.id, {
    $unset: { biometricKey: 1 },
  });

  res.status(200).json({
    status: "success",
    message: "User logged out successfully",
  });
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

// todo: SET PASSWORD
exports.setPassword = catchAsync(async (req, res, next) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return next(new AppError("Please provide email and password", 400));
  }

  const user = await User.findOne({ email });
  if (!user) {
    return next(new AppError("User not found", 404));
  }

  if (!user.email_verified) {
    return next(new AppError("Email not verified", 400));
  }

  // if (user.password) {
  //   return next(new AppError("Password already set! use reset password", 400));
  // }

  const hashedPassword = await bcrypt.hash(password, 12);

  await User.findOneAndUpdate(
    {
      email,
    },
    {
      password: hashedPassword,
    }
  );

  createSendToken(user, 200, res);
});

// todo: UPDATE PROFILE
exports.updateProfile = catchAsync(async (req, res, next) => {
  const { name, gender, date_of_birth } = req.body;
  const user = req.user;

  if (!name || !gender || !date_of_birth) {
    return next(
      new AppError("Please provide name, gender and date_of_birth", 400)
    );
  }

  const updated = await User.findByIdAndUpdate(
    user.id,
    {
      name,
      gender,
      date_of_birth,
    },

    {
      new: true,
      runValidators: true,
    }
  );

  res.status(200).json({
    status: "success",
    data: {
      user: updated,
    },
  });
});

// todo: SET PIN
exports.setLoginPinFirst = catchAsync(async (req, res, next) => {
  const { login_pin } = req.body;
  const user = req.user;

  if (!login_pin) {
    return next(new AppError("Please provide login pin", 400));
  }

  if (login_pin.length !== 4) {
    return next(new AppError("Please provide 4 digit pin", 400));
  }

  // pin saved as hashed
  const hashedPin = await bcrypt.hash(login_pin, 12);

  // if (user.login_pin) {
  //   return next(new AppError("Pin already set! use reset pin", 400));
  // }

  const updated = await User.findByIdAndUpdate(
    user.id,
    {
      login_pin: hashedPin,
    },

    {
      new: true,
      runValidators: true,
    }
  );

  res.status(200).json({
    status: "success",
    data: {
      user: updated,
    },
  });
});

// todo: VERIFY PIN
exports.verifyLoginPin = catchAsync(async (req, res, next) => {
  const { login_pin } = req.body;
  const user = req.user;

  if (!login_pin) {
    return next(new AppError("Please provide login pin", 400));
  }

  if (login_pin.length !== 4) {
    return next(new AppError("Please provide 4 digit pin", 400));
  }

  const currentTime = Date.now();
  const blockedUntil = new Date(user.blocked_until_pin).getTime();

  const isBlocked = blockedUntil > currentTime;

  if (isBlocked) {
    // Convert blockedUntil to a readable time (12-hour format)
    const unblockTime = new Date(blockedUntil).toLocaleTimeString("en-US", {
      hour: "2-digit",
      minute: "2-digit",
      hour12: true, // Ensures 12-hour format with AM/PM
    });

    return next(
      new AppError(
        `You are blocked from logging in. Please try again at ${unblockTime}.`,
        401
      )
    );
  }

  // Verify pin
  const correct = await user.comparePin(login_pin);

  if (!correct) {
    const attemptsLeft = 3 - user.wrong_pin_attempts;
    if (attemptsLeft > 0) {
      return next(
        new AppError(
          `Incorrect Credentials. ${attemptsLeft} attempts left`,
          401
        )
      );
    } else {
      return next(new AppError(`Incorrect pin.`, 401));
    }
  }

  res.status(200).json({
    status: "success",
    data: {
      user,
    },
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
