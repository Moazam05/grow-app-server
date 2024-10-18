require("dotenv").config();
const jwt = require("jsonwebtoken");
const { promisify } = require("util");
const bcrypt = require("bcryptjs");
const NodeRSA = require("node-rsa");
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

exports.verifyBiometric = catchAsync(async (req, res, next) => {
  const { signature } = req.body;
  const user = req.user;

  if (!signature) {
    return next(new AppError("Signature is required", 400));
  }

  if (!user.biometricKey) {
    return next(new AppError("Biometric key not found", 400));
  }

  const isVerifiedSignature = await verifySignature(
    signature,
    user.id,
    user.biometricKey
  );

  if (!isVerifiedSignature) {
    return next(new AppError("Biometric verification failed", 401));
  }

  res.status(200).json({
    status: "success",
    message: "Biometric verification successful",
  });
});

async function verifySignature(signature, payload, publicKey) {
  const publicKeyBuffer = Buffer.from(publicKey, "base64");
  const key = new NodeRSA();

  // Import the public key as a PEM-encoded key (default format used in biometric systems)
  key.importKey(publicKeyBuffer, "public-der");

  // Ensure the correct hash scheme (e.g., sha256) is used for verifying
  const signatureVerified = key.verify(
    Buffer.from(payload), // Payload in Buffer format
    signature, // Signature in base64 format
    "utf8", // Input encoding of the payload
    "base64" // Output encoding of the signature
  );

  return signatureVerified;
}
