require("dotenv").config();
const { OAuth2Client } = require("google-auth-library");
const jwt = require("jsonwebtoken");
// Custom Imports
const AppError = require("../utils/appError");
const catchAsync = require("../utils/catchAsync");
const User = require("../models/userModel");

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

const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

exports.googleLogin = catchAsync(async (req, res, next) => {
  const { tokenId } = req.body;

  if (!tokenId) {
    return next(new AppError("Token is required", 400));
  }

  // Verify the Google token using the OAuth2 client
  const ticket = await googleClient.verifyIdToken({
    idToken: tokenId,
    audience: process.env.GOOGLE_CLIENT_ID,
  });

  const payload = ticket.getPayload();

  const { email, name } = payload;

  if (!email || !name) {
    return next(new AppError("Invalid Google token", 400));
  }

  // Find the user by email, if they don't exist, create one
  const user = await User.findOneAndUpdate(
    { email }, // Filter by email
    {
      name, // Update name
      email_verified: true, // Set email_verified to true
      email, // Ensure email is set
    },
    {
      new: true, // Return the newly updated or created user
      upsert: true, // Create a new user if one doesn't exist
      runValidators: true, // Ensure validators are run
    }
  );

  // Send token and response
  createSendToken(user, 200, res);
});
