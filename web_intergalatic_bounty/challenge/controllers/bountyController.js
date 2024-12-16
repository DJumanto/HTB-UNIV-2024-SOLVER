const BountyModel = require("../models/bountyModel");
const { sanitizeHTMLContent, fetchURL } = require("../util");
const mergedeep = require("@christopy/mergedeep");
const { visitReport } = require("../bot");

const home = (req, res) => {
  return res.render("home", { user: req.user });
};

const getBountyView = (req, res) => {
  return res.render("showBounty", { user: req.user });
};

const addBountyView = (req, res) => {
  return res.render("addBounty", { user: req.user });
};

const editBountyView = (req, res) => {
  return res.render("editBounty", { user: req.user });
};

const trasmitView = (req, res) => {
  return res.render("transmit", { user: req.user });
};

const transmitAPI = async (req, res) => {
  const { url } = req.body;

  if (!url) {
    return res.status(400).json({ message: "URL is required" });
  }

  const responseBody = await fetchURL(url);

  res.status(200).json({
    message: "Request successful",
    responseBody,
  });
};

const getBountiesAPI = async (req, res) => {
  try {
    const data = await BountyModel.findAll();
    return res.json(data);
  } catch (err) {
    return res.status(500).json({ message: "Error fetching bounties" });
  }
};

const getBountyAPI = async (req, res) => {
  try {
    const data = await BountyModel.findByPk(req.params.id);
    if (!data) {
      return res.status(404).json({ message: "Bounty not found" });
    }
    return res.json(data);
  } catch (err) {
    return res.status(500).json({ message: "Error fetching data" });
  }
};

const addBountiesAPI = async (req, res) => {
  const { status = "unapproved", ...bountyData } = req.body;

  const sanitizedBountyData = sanitizeHTMLContent(bountyData);

  try {
    const newBounty = await BountyModel.create({
      ...sanitizedBountyData,
      status,
    });
    return res.status(200).json({ message: "OK", data: newBounty });
  } catch (err) {
    return res
      .status(500)
      .json({ message: "Error adding bounty", error: err.message });
  }
};

const editBountiesAPI = async (req, res) => {
  const { ...bountyData } = req.body;
  try {
    const data = await BountyModel.findByPk(req.params.id, {
      attributes: [
        "target_name",
        "target_aliases",
        "target_species",
        "last_known_location",
        "galaxy",
        "star_system",
        "planet",
        "coordinates",
        "reward_credits",
        "reward_items",
        "issuer_name",
        "issuer_faction",
        "risk_level",
        "required_equipment",
        "posted_at",
        "status",
        "image",
        "description",
        "crimes",
        "id",
      ],
    });

    if (!data) {
      return res.status(404).json({ message: "Bounty not found" });
    }

    const updated = mergedeep(data.toJSON(), bountyData);

    await data.update(updated);

    return res.json(updated);
  } catch (err) {
    console.log(err);
    return res.status(500).json({ message: "Error fetching data" });
  }
};

const reportAPI = async (req, res) => {
  const id = req.params.id;

  if (!id) {
    return res.status(400).send("ID is required");
  }

  res.send(`Admin will review it`);

  try {
    await visitReport(id);
  } catch (err) {
    console.error("Error in visitReport:", err);
  }
};

module.exports = {
  getBountiesAPI,
  addBountiesAPI,
  getBountyAPI,
  home,
  getBountyView,
  addBountyView,
  editBountyView,
  editBountiesAPI,
  trasmitView,
  transmitAPI,
  reportAPI,
};
