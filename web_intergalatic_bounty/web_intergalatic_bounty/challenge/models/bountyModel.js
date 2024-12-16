const { DataTypes } = require("sequelize");
const sequelize = require("../database").sequelize;

const Bounty = sequelize.define("Bounty", {
  target_name: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  target_aliases: {
    type: DataTypes.TEXT,
    allowNull: true,
  },
  target_species: {
    type: DataTypes.STRING,
    allowNull: true,
  },
  last_known_location: {
    type: DataTypes.STRING,
    allowNull: true,
  },
  galaxy: {
    type: DataTypes.STRING,
    allowNull: true,
  },
  star_system: {
    type: DataTypes.STRING,
    allowNull: true,
  },
  planet: {
    type: DataTypes.STRING,
    allowNull: true,
  },
  coordinates: {
    type: DataTypes.STRING,
    allowNull: true,
  },
  reward_credits: {
    type: DataTypes.DECIMAL(10, 2),
    allowNull: true,
  },
  reward_items: {
    type: DataTypes.TEXT,
    allowNull: true,
  },
  issuer_name: {
    type: DataTypes.STRING,
    allowNull: true,
  },
  issuer_faction: {
    type: DataTypes.STRING,
    allowNull: true,
  },
  risk_level: {
    type: DataTypes.STRING,
    allowNull: true,
  },
  required_equipment: {
    type: DataTypes.TEXT,
    allowNull: true,
  },
  posted_at: {
    type: DataTypes.STRING,
    allowNull: true,
  },
  status: {
    type: DataTypes.STRING,
    allowNull: true,
  },
  image: {
    type: DataTypes.STRING,
    allowNull: true,
  },
  description: {
    type: DataTypes.TEXT,
    allowNull: true,
  },
  crimes: {
    type: DataTypes.STRING,
    allowNull: true,
  },
});

Bounty.getAllBounty = async () => {
  try {
    return await Bounty.findAll();
  } catch (err) {
    throw new Error("Error fetching all bounties");
  }
};

Bounty.getBounty = async (id) => {
  try {
    return await Bounty.findByPk(id);
  } catch (err) {
    throw new Error("Error fetching bounty");
  }
};

Bounty.getDuplicates = async () => {
  try {
    const duplicates = await sequelize.query(
      `SELECT * FROM bounties AS b
       INNER JOIN (SELECT target_name, target_aliases, COUNT(*) as duplicate_count
                   FROM bounties GROUP BY target_name, target_aliases
                   HAVING COUNT(*) > 1) AS dup
       ON b.target_name = dup.target_name AND b.target_aliases = dup.target_aliases`,
      { type: sequelize.QueryTypes.SELECT },
    );
    return duplicates;
  } catch (err) {
    throw new Error("Error fetching duplicate bounties");
  }
};

Bounty.addBounty = async (bountyData) => {
  try {
    const bounty = await Bounty.create(bountyData);
    return bounty;
  } catch (err) {
    throw new Error("Error adding bounty");
  }
};

module.exports = Bounty;
