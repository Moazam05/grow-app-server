const express = require("express");
const authController = require("../controllers/authController");
const otpController = require("../controllers/otpController");

const router = express.Router();

// todo: AUTH ROUTES
router.post("/login", authController.login);

router.post("/check-email", authController.checkEmail);
router.post("/set-password", authController.setPassword);
router.put("/profile", authController.protect, authController.updateProfile);
router.post(
  "/set-pin",
  authController.protect,
  authController.setLoginPinFirst
);

// todo: OTP ROUTES
router.post("/verify-otp", otpController.verifyOTP);
router.post("/send-otp", otpController.sendOTP);

module.exports = router;
