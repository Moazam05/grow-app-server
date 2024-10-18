require("dotenv").config();
const jwt = require("jsonwebtoken");
const { promisify } = require("util");
const bcrypt = require("bcryptjs");
// Custom Imports
const User = require("../models/userModel");
const catchAsync = require("../utils/catchAsync");
const AppError = require("../utils/appError");

exports.uploadBiometric = catchAsync(async (req, res, next) => {
  const { public_key } = req.body;
  const user = req.user;

  if (!public_key) {
    return next(new AppError("Public key is required", 400));
  }

  const updatedUser = await User.findByIdAndUpdate(
    user.id,
    { biometricKey: public_key },
    { new: true, runValidators: true }
  );

  res.status(200).json({
    status: "success",
    message: "Biometric key uploaded successfully",
    data: {
      user: updatedUser,
    },
  });
});
