const crypto = require("crypto");
const bcrypt = require("bcryptjs");

const User = require("./user");

const { isEmpty, isMatching, comparePasswords } = require("../utils/validate");
const newError = require("../utils/newError");
const sendEmail = require("../utils/sendEmail");
const required = require("../utils/requireEnvVar");

async function loginUser(userData) {
  try {
    const { email, password } = userData;

    const foundUser = await User.findOne({ email });
    if (!foundUser)
      return { didSucceed: false, message: "Invalid email or password." };

    const doMatch = await comparePasswords(password, foundUser.password);
    if (!doMatch)
      return { didSucceed: false, message: "Invalid email or password." };

    return { didSucceed: true, message: "", user: foundUser };
  } catch (error) {
    throw newError("Failed to login user", error);
  }
}

// ! VALIDATION will be implemented during course section S18 - Understanding Validation
async function singupUser(userData) {
  try {
    const { email, password, confirmPassword } = userData;
    const userExists = await User.findOne({ email });

    // ^ return will be handled in controller, calling res.redirect
    if (userExists)
      return {
        didSucceed: false,
        message: "Email already in use. Please provide different email adress.",
      };

    const hashedPwd = await bcrypt.hash(password, 12);
    const user = new User({
      email,
      password: hashedPwd,
      cart: { items: [] },
    });

    await user.save();

    const dummyID = crypto.randomUUID();
    await sendEmail(
      email,
      "Signup succeeded!",
      `<h1>You succesfully signed up!</h1><p>Dummy ID: ${dummyID}</p>`
    );
    return { didSucceed: true, message: "User succesfully created!" };
  } catch (error) {
    throw newError("Failed to signup user", error);
  }
}

async function resetPassword(email) {
  return new Promise((resolve, reject) => {
    crypto.randomBytes(32, async (err, buffer) => {
      if (err)
        return reject(newError("Generating crypto random data failed", err));

      const token = buffer.toString("hex");

      try {
        const foundUser = await User.findOne({ email });

        if (!foundUser)
          return resolve({
            didSucceed: false,
            message: "No email found. Please provide a valid email adress.",
          });

        const PORT = required("SERVER_PORT") || 3000;
        const ONE_HOUR = 60 * 60 * 1000; // 1h in miliseconds
        const dummyID = crypto.randomUUID();

        foundUser.resetPasswordToken.token = token;
        foundUser.resetPasswordToken.expiresAt = Date.now() + ONE_HOUR;
        await foundUser.save();

        // return resolve(true); // DEBUGGING
        await sendEmail(
          foundUser.email,
          "Password Reset Link",
          `
          <h1>You requested a password reset</h1>
          <p>Click this <a href="http://localhost:${PORT}/reset-password/${token}">link</a> to set a new password.</p>
          <p>Dummy ID: ${dummyID}</p> 
          `
        );

        return resolve({
          didSucceed: true,
          message: "Email was sent. Check your inbox!",
        });
      } catch (error) {
        throw newError("Failed to reset user password", error);
      }
    });
  });
}

// * looks for req.query.token in DB and returns matching user._id if token was found and not expired
async function validateToken(token) {
  // console.log("resetPassword token:", token); // DEBUGGING
  try {
    const matchingUser = await User.findOne({
      "resetPasswordToken.token": token,
      "resetPasswordToken.expiresAt": { $gt: Date.now() },
    });
    if (!matchingUser)
      return {
        didSucceed: false,
        message: "Invalid or expired password reset link",
      };
    // console.log("matchingUser based on resetPassword token: ", matchingUser); // DEBUGGING

    const matchingUserId = matchingUser._id;
    const matchingUserHashedPwd = matchingUser.password;
    return {
      didSucceed: true,
      matchingUserId,
      matchingUserHashedPwd,
    };
  } catch (error) {
    throw newError("Could not validate reset password token", error);
  }
}

// * reads userId from hidden `token` value & re-validates, checks DB for matching _id based on token and updates password
async function updatePassword(formData) {
  const { password, confirmPassword, token } = formData;

  if (
    isEmpty([password, confirmPassword]) ||
    !isMatching(password, confirmPassword)
  )
    return {
      didSucceed: false,
      message: "Passwords cannot be empty and must match",
      toLoginPage: false,
    };

  try {
    // ^ re-validate token to prevent tampering and (some) edge cases
    const { didSucceed, message, matchingUserId, matchingUserHashedPwd } =
      await validateToken(token);
    if (!didSucceed)
      return {
        didSucceed,
        message,
        toLoginPage: true,
      };

    const doMatch = await comparePasswords(password, matchingUserHashedPwd);
    if (doMatch)
      return {
        didSucceed: false,
        message: "New password cannot match old password",
        toLoginPage: false,
      };

    const hashedPwd = await bcrypt.hash(password, 12);

    const updated = await User.findOneAndUpdate(
      {
        _id: matchingUserId,
      },
      {
        $set: { password: hashedPwd },
        $unset: {
          resetPasswordToken: {
            token: "",
            expiresAt: "",
          },
        },
      },
      { new: false }
    );
    if (!updated)
      return {
        didSucceed: false,
        message: "Invalid or expired link",
        toLoginPage: false,
      };

    return {
      didSucceed: true,
      message: "Password updated succesfully!",
      toLoginPage: true,
    };
  } catch (error) {
    throw newError("Could not update password", error);
  }
}

module.exports = {
  loginUser,
  singupUser,
  resetPassword,
  validateToken,
  updatePassword,
};
