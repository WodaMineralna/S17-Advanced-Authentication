const { loginUser, singupUser, resetPassword } = require("../models/auth");

const newError = require("../utils/newError");

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
  const user = await loginUser({ email, password });

  if (!user) {
    req.flash("error", "Invalid email or password.");
    return res.redirect("/login");
  } else {
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
  const userExists = await singupUser({ email, password, confirmPassword });

  if (userExists === true) {
    req.flash(
      "error",
      "Email already in use. Please provide different email adress."
    );
    return res.redirect("/signup");
  }
  return res.redirect("/");
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
  const matchingUser = await resetPassword(email);

  if (matchingUser === false) {
    req.flash("error", "No email found. Please provide a valid email adress.");
    return res.redirect("/reset-password");
  }
  if (matchingUser === true) {
    req.flash("info", "Email was sent. Check your inbox!");
    return res.redirect("/login");
  }
};
};
