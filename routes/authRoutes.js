const express = require("express");
const authController = require("../controllers/authController");

const router = express.Router();

// todo: AUTH ROUTES
router.post("/login", authController.login);

router.post("/check-email", authController.checkEmail);
router.post("/verify-otp", authController.verifyOTP);
router.post("/send-otp", authController.sendOTP);
router.post("/set-password", authController.setPassword);

module.exports = router;
