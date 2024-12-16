const { createToken } = require("../util");
const User = require("../models/userModel");
const emailAddresses = require('email-addresses');

const authIndex = (req, res) => {
  return res.render("index");
};

const logout = (req, res) => {
  res.clearCookie("auth", { path: "/" });
  res.redirect("/");
};

const registerAPI = async (req, res) => {
  const { email, password, role = "guest" } = req.body;
  const emailDomain = emailAddresses.parseOneAddress(email)?.domain;

  if (!emailDomain || emailDomain !== 'interstellar.htb') {
    return res.status(200).json({ message: 'Registration is not allowed for this email domain' });
  }

  try {
    await User.createUser(email, password, role);
    return res.json({ message: "User registered. Verification email sent.", status: 201 });
  } catch (err) {
    return res.status(500).json({ message: err.message, status: 500 });
  }
};

const loginAPI = async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.loginUser(email, password);

    const token = createToken(user);
    return res.status(200).json({
      message: "Login successful",
      token,
      role: user.role,
      status: 200,
    });
  } catch (err) {
    return res.status(403).json({ message: err.message, status: 403 });
  }
};

const verifyAPI = async (req, res) => {
  const { email, code } = req.body;

  try {
    await User.verifyAccount(email, code);
    return res.json({ message: "Account verified successfully", status: 200 });
  } catch (err) {
    return res.status(400).json({ message: err.message, status: 400 });
  }
};

const resendVerificationAPI = async (req, res) => {
  const { email } = req.body;

  try {
    await User.resendVerificationCode(email);
    return res.json({ message: "New verification code sent", status: 200 });
  } catch (err) {
    return res.status(400).json({ message: err.message, status: 400 });
  }
};

module.exports = { registerAPI, loginAPI, verifyAPI, resendVerificationAPI, authIndex, logout };
