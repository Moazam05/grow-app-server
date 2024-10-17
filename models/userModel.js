const mongoose = require("mongoose");

const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      minlength: 3,
      required: [true, "Please tell us your name!"],
    },
  },
  {
    timestamps: true,
  }
);

const User = new mongoose.model("User", userSchema);
module.exports = User;
