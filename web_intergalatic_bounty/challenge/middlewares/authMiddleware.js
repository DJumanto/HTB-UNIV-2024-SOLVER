const { verifyToken } = require("../util");

const authMiddleware = (req, res, next) => {
  const authCookie = req.cookies.auth;

  if (!authCookie)
    return res.status(401).json({ message: "No auth cookie provided" });

  const user = verifyToken(authCookie);
  if (user != false && user != undefined) {
    req.user = user;
    return next();
  }

  return res.status(401).json({ message: "Unauthenticated" });
};

module.exports = authMiddleware;
