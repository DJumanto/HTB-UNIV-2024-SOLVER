const { DataTypes } = require("sequelize");
const sequelize = require("../database").sequelize;
const { generateRandomCode, sendVerificationEmail } = require("../util");

const User = sequelize.define("User", {
  email: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true,
  },
  password: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  verificationCode: {
    type: DataTypes.STRING,
    allowNull: true,
  },
  isVerified: {
    type: DataTypes.BOOLEAN,
    defaultValue: false,
  },
  role: {
    type: DataTypes.ENUM("user", "admin"),
    defaultValue: "user",
  },
});

User.createUser = async function (email, password, role = "guest") {
  try {
    const verificationCode = generateRandomCode();
    const user = await this.create({ email, password, role, verificationCode });
    return user;
  } catch (err) {
    throw new Error("Error creating user");
  }
};

User.getUserByEmail = async function (email) {
  try {
    return await this.findOne({ where: { email } });
  } catch (err) {
    throw new Error("Error fetching user");
  }
};

User.loginUser = async function (email, password) {
  try {
    const user = await this.findOne({ where: { email, password } });
    if (!user) {
      throw new Error("Invalid credentials");
    }
    if (!user.isVerified) {
      throw new Error("Account not verified");
    }
    return user;
  } catch (err) {
    throw new Error(err.message || "Error logging in user");
  }
};

User.verifyAccount = async function (email, code) {
  try {
    const user = await this.getUserByEmail(email);
    if (!user || user.verificationCode !== code) {
      throw new Error("Invalid verification code");
    }
    user.isVerified = true;
    user.verificationCode = null;
    await user.save();
    return user;
  } catch (err) {
    throw new Error(err.message || "Error verifying account");
  }
};

User.resendVerificationCode = async function (email) {
  try {
    const user = await this.getUserByEmail(email);
    if (!user) {
      throw new Error("User not found");
    }
    if (user.isVerified) {
      throw new Error("User is already verified");
    }
    const newCode = generateRandomCode();
    user.verificationCode = newCode;
    await user.save();
    await sendVerificationEmail(email, newCode);
    return user;
  } catch (err) {
    throw new Error(err.message || "Error resending verification code");
  }
};

module.exports = User;
