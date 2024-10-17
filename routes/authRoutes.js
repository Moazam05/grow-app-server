const express = require("express");
const authController = require("../controllers/authController");

const router = express.Router();

// todo: AUTH ROUTES
router.post("/register", authController.register);
router.post("/login", authController.login);

router.post("/check-email", authController.checkEmail);
router.post("/verify-otp", authController.verifyOTP);

module.exports = router;
