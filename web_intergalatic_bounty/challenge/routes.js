const express = require("express");
const authController = require("./controllers/authController");
const adminMiddleware = require("./middlewares/adminMiddleware");
const bountyController = require("./controllers/bountyController");
const authMiddleware = require("./middlewares/authMiddleware");
const router = express.Router();

router.get("/", authController.authIndex);
router.get("/home", authMiddleware, bountyController.home);
router.get("/bounty/:id", authMiddleware, bountyController.getBountyView);
router.get("/add-bounty", authMiddleware, bountyController.addBountyView);
router.get(
  "/edit/:id",
  [authMiddleware, adminMiddleware],
  bountyController.editBountyView,
);
router.get(
  "/transmit",
  [authMiddleware, adminMiddleware],
  bountyController.trasmitView,
);

router.get("/logout", authController.logout);

router.post("/api/register", authController.registerAPI);
router.post("/api/login", authController.loginAPI);
router.post("/api/sendEmail", authController.resendVerificationAPI);
router.post("/api/verify", authController.verifyAPI);

router.get("/api/bounties", authMiddleware, bountyController.getBountiesAPI);
router.post("/api/bounties", authMiddleware, bountyController.addBountiesAPI);
router.put(
  "/api/bounties/:id",
  [authMiddleware, adminMiddleware],
  bountyController.editBountiesAPI,
);
router.post(
  "/api/transmit",
  [authMiddleware, adminMiddleware],
  bountyController.transmitAPI,
);
router.get("/api/report/:id", authMiddleware, bountyController.reportAPI);
router.get("/api/bounties/:id", authMiddleware, bountyController.getBountyAPI);
router.get("/api/getDuplicates", authMiddleware);
module.exports = router;
