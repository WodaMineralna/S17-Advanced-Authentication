const {
  loginUser,
  singupUser,
  resetPassword,
  validateToken,
  updatePassword,
} = require("../models/auth");

const newError = require("../utils/newError");

const PLACEHOLDER_MESSAGE = "Something went wrong...";

exports.getLogin = (req, res, next) => {
  res.render("auth/login", {
    path: "/login",
    pageTitle: "Login",
    errorMessage: req.flash("error"),
    infoMessage: req.flash("info"),
  });
};

exports.postLogin = async (req, res, next) => {
  const { email, password } = req.body;
  const {
    didSucceed,
    message = PLACEHOLDER_MESSAGE,
    user,
  } = await loginUser({ email, password });

  if (!didSucceed) {
    req.flash("error", message);
    return res.redirect("/login");
  }
  if (didSucceed) {
    req.session.user = user;
    req.session.loggedIn = true;
    req.session.save((err) => {
      if (err) throw newError("Failed to log in", err);
      res.redirect("/");
    });
  }
};

exports.postLogout = async (req, res, next) => {
  req.session.destroy((err) => {
    if (err) throw newError("Failed to logout", err);
    res.redirect("/");
  });
};

exports.getSignup = (req, res, next) => {
  res.render("auth/signup", {
    path: "/signup",
    pageTitle: "Signup",
    errorMessage: req.flash("error"),
  });
};

// ! VALIDATION will be implemented during course section S18 - Understanding Validation
exports.postSignup = async (req, res, next) => {
  const { email, password, confirmPassword } = req.body;
  const { didSucceed, message = PLACEHOLDER_MESSAGE } = await singupUser({
    email,
    password,
    confirmPassword,
  });

  if (!didSucceed) {
    req.flash("error", message);
    return res.redirect("/signup");
  }
  if (didSucceed) {
    req.flash("info", message);
    return res.redirect("/login");
  }
};

exports.getResetPassword = (req, res, next) => {
  res.render("auth/reset-password", {
    path: "/reset-password",
    pageTitle: "Reset Password",
    errorMessage: req.flash("error"),
  });
};

exports.postResetPassword = async (req, res, next) => {
  const { email } = req.body;
  const { didSucceed, message = PLACEHOLDER_MESSAGE } = await resetPassword(
    email
  );

  if (!didSucceed) {
    req.flash("error", message);
    return res.redirect("/reset-password");
  }
  if (didSucceed) {
    req.flash("info", message);
    return res.redirect("/login");
  }
};

exports.getResetPasswordForm = async (req, res, next) => {
  const token = req.params.token;
  const { didSucceed, message = PLACEHOLDER_MESSAGE } = await validateToken(
    token
  );

  if (!didSucceed) {
    req.flash("error", message);
    return res.redirect("/login");
  }
  if (didSucceed) {
    return res.render("auth/form-reset-password", {
      path: "/form-reset-password",
      pageTitle: "Reset Password Form",
      errorMessage: req.flash("error"),
      token,
    });
  }
};

exports.postResetPasswordForm = async (req, res, next) => {
  const { password, confirmPassword, token } = req.body;
  const {
    didSucceed,
    message = PLACEHOLDER_MESSAGE,
    toLoginPage,
  } = await updatePassword({
    password,
    confirmPassword,
    token,
  });

  if (!didSucceed) {
    req.flash("error", message);
    if (toLoginPage) return res.redirect("/login");
    return res.redirect(req.get("Referer") || "/");
  }
  if (didSucceed) {
    req.flash("info", message);
    return res.redirect("/login");
  }
};
