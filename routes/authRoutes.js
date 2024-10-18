const express = require("express");
const authController = require("../controllers/authController");
const otpController = require("../controllers/otpController");
const oauthController = require("../controllers/oauthController");
const biometricController = require("../controllers/biometricController");

const router = express.Router();

// todo: AUTH ROUTES
router.post("/login", authController.login);

router.post("/check-email", authController.checkEmail);
router.post("/set-password", authController.setPassword);

// todo: OTP ROUTES
router.post("/verify-otp", otpController.verifyOTP);
router.post("/send-otp", otpController.sendOTP);

// todo: OAuth ROUTES
router.post("/google-login", oauthController.googleLogin);

// todo: PROTECTED --------------------- ROUTES
router.use(authController.protect);

router.put("/profile", authController.updateProfile);
router.post("/set-pin", authController.setLoginPinFirst);
router.post("/verify-pin", authController.verifyLoginPin);
router.post("/upload-biometric", biometricController.uploadBiometric);

module.exports = router;
