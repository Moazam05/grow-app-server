const express = require("express");
const authController = require("../controllers/authController");

const router = express.Router();

// PROTECTED ROUTES
router.use(authController.protect);

router.get("/", (req, res) => {
  res.send("Stocks");
});

module.exports = router;
