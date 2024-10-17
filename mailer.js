const nodemailer = require("nodemailer");
require("dotenv").config();
const otpGenerator = require("otp-generator");
// Custom Imports
const User = require("./models/userModel");

// CREATE TRANSPORTER
const transporter = nodemailer.createTransport({
  service: "Gmail",
  auth: {
    user: process.env.GMAIL_USER,
    pass: process.env.GMAIL_PASS,
  },
});

// FUNCTION TO SEND EMAIL
module.exports.sendEmail = async (email, subject, htmlContent, publicName) => {
  try {
    const user = await User.findOne({
      name: publicName,
    });
    if (!user) {
      return next(new AppError("User not found", 404));
    }

    // SEND EMAIL
    const info = await transporter.sendMail({
      from: process.env.GMAIL_USER,
      to: email,
      subject: subject,
      html: htmlContent,
    });

    return info;
  } catch (error) {
    console.error("Error while sending email: ", error);
  }
};

module.exports.mailSender = async (email, otp, otp_type) => {
  try {
    const info = await transporter.sendMail({
      from: process.env.GMAIL_USER,
      to: email,
      subject: "Grow App",
      text: `<h1>Your OTP is ${otp}</h1>`,
    });

    return info;
  } catch (error) {
    console.log(error);
    throw new Error("Error sending email");
  }
};

module.exports.generateOTP = async () => {
  return otpGenerator.generate(6, {
    upperCaseAlphabets: false,
    lowerCaseAlphabets: false,
    specialChars: false,
  });
};
