const express = require("express");
const router = express.Router();

const authController = require("../controllers/auth");
const catchErrAsync = require("../utils/catchErrAsync");

router.get("/login", authController.getLogin);

router.post("/login", catchErrAsync(authController.postLogin));

router.post("/logout", catchErrAsync(authController.postLogout));

router.get("/signup", authController.getSignup);

router.post("/signup", catchErrAsync(authController.postSignup));

router.get("/reset-password", authController.getResetPassword);

router.post("/reset-password", catchErrAsync(authController.postResetPassword));

router.get(
  "/reset-password/:token",
  catchErrAsync(authController.getResetPasswordForm)
);

router.post(
  "/update-password",
  catchErrAsync(authController.postResetPasswordForm)
);

module.exports = router;
