const crypto = require("crypto");
const bcrypt = require("bcryptjs");

const User = require("./user");

const newError = require("../utils/newError");
const sendEmail = require("../utils/sendEmail");
const required = require("../utils/requireEnvVar");

async function loginUser(userData) {
  try {
    const { email, password } = userData;

    const foundUser = await User.findOne({ email });
    if (!foundUser) return false;

    const doMatch = await bcrypt.compare(password, foundUser.password);
    if (!doMatch) return false;

    return foundUser;
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
    if (userExists) return true;

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
    return false; // user does not already exist
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

        if (!foundUser) return resolve(false);

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

        return resolve(true);
      } catch (error) {
        throw newError("Failed to reset user password", error);
      }
    });
  });
}

module.exports = { loginUser, singupUser, resetPassword };
