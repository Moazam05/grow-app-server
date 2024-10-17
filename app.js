const express = require("express");
const morgan = require("morgan");
const colors = require("colors");
const cors = require("cors");
const path = require("path");
require("dotenv").config();
require("express-async-errors");
// Custom Imports
const AppError = require("./utils/appError");
const globalErrorHandler = require("./controllers/errorController");
// const userRouter = require("./routes/userRoutes");

const corsOptions = {
  origin: "*",
  methods: "*",
  allowedHeaders: "*",
};

const app = express();
app.use(cors(corsOptions));

if (process.env.NODE_ENV === "development") {
  app.use(morgan("dev"));
}
app.use(
  express.json({
    limit: "3mb",
  })
);

app.use((req, res, next) => {
  req.requestTime = new Date().toISOString();
  next();
});

// ROUTES
// app.use("/api/v1/users", userRouter);

// PRODUCTION SETUP
if (process.env.NODE_ENV === "production") {
  // const __dirname = path.resolve();
  // app.use(express.static("../client/build"));
  // app.get("*", (req, res) => {
  //   res.sendFile(path.resolve(__dirname, "../client/build", "index.html"));
  // });
} else {
  app.get("/", (req, res) => {
    res.send("Grow App API is running...");
  });
}

app.all("*", (req, res, next) => {
  next(new AppError(`Can't find ${req.originalUrl} on this server!`, 404));
});

app.use(globalErrorHandler);

module.exports = app;
