const adminMiddleware = (req, res, next) => {
  if (!req.user)
    return res.status(401).json({ message: "No auth cookie provided" });

  if (req.user.role != "admin") {
    return res.status(403).json({ message: "Unauthorized" });
  }

  next();
};

module.exports = adminMiddleware;
