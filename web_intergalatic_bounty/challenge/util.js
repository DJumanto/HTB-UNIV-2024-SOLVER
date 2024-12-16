const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const sanitizeHtml = require("sanitize-html");
const needle = require("needle");
const nodemailer = require("nodemailer");
const SECRET_KEY = crypto.randomBytes(32).toString("hex");
const generateRandomCode = () => crypto.randomBytes(16).toString("hex");

const transporter = nodemailer.createTransport({
  host: "127.0.0.1",
  port: 1025,
  secure: false,
});

const sendVerificationEmail = async (email, code) => {
  const mailOptions = {
    from: "no-reply@interstellar.htb",
    to: email,
    subject: "Email Verification",
    html: `Your verification code is: ${code}`,
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log(`Verification email sent to ${email}`);
  } catch (error) {
    console.error("Error sending email:", error);
    throw new Error("Unable to send verification email");
  }
};

const createToken = (user) => {
  return jwt.sign({ id: user.id, email: user.email, role: user.role }, SECRET_KEY, {
    expiresIn: "1h",
  });
};

const verifyToken = (token) => {
  return jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) return false;

    return decoded;
  });
};

const sanitizeHTMLContent = (data) => {
  return Object.entries(data).reduce((acc, [key, value]) => {
    acc[key] = sanitizeHtml(value, {
      allowedTags: sanitizeHtml.defaults.allowedTags.concat([
        "math",
        "style",
        "svg",
      ]),
      allowVulnerableTags: true,
    });
    return acc;
  }, {});
};

const fetchURL = async (url) => {
  if (!url.startsWith("http://") && !url.startsWith("https://")) {
    throw new Error("Invalid URL: URL must start with http or https");
  }

  const options = {
    compressed: true,
    follow_max: 0,
  };

  return new Promise((resolve, reject) => {
    needle.get(url, options, (err, resp, body) => {
      if (err) {
        return reject(new Error("Error fetching the URL: " + err.message));
      }
      resolve(body);
    });
  });
};

module.exports = { sendVerificationEmail, createToken, verifyToken, sanitizeHTMLContent, fetchURL, generateRandomCode };
