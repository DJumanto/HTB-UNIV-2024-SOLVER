const { Sequelize } = require("sequelize");
const crypto = require("crypto");

class Database {
  constructor() {
    this.sequelize = new Sequelize({
      dialect: "sqlite",
      storage: "./database.sqlite",
      logging: false,
    });
  }

  async connect() {
    try {
      await this.sequelize.authenticate();
      console.log("Connected to the SQLite database using Sequelize");
    } catch (error) {
      console.error("Unable to connect to the database:", error);
    }
  }

  async migrate() {
    try {
      const User = require("./models/userModel");
      const Bounty = require("./models/bountyModel");

      await this.sequelize.sync({ force: true });
      console.log("Database synced successfully.");
      await User.create({
        email: "admin@interstellar.htb",
        password: crypto.randomBytes(32).toString("hex"),
        role: "admin",
        isVerified: true,
      });

      await Bounty.bulkCreate([
        {
          target_name: "Zorak the Destroyer",
          target_aliases: "Butcher of Argon, Scourge of Nebula 7",
          target_species: "Kronovian",
          last_known_location: "Xandar",
          galaxy: "Andromeda",
          star_system: "Beta-54",
          planet: "Xandar",
          coordinates: "238.45, 482.78, 112.3",
          crimes:
            "Planetary invasion, War crimes, Destruction of military outposts",
          reward_credits: 50000.0,
          reward_items: "Starship upgrade, Plasma Blaster Mk II",
          issuer_name: "Xclow3n",
          issuer_faction: "Empire",
          risk_level: "high",
          required_equipment:
            "Stealth Field Generator, Advanced Targeting System",
          posted_at: "2024-09-01",
          status: "open",
          image: "/static/images/Zora.png",
          description:
            "<p>Zorak the Destroyer is wanted for <strong>multiple planetary invasions</strong>. His signature weapon, a <i>Plasma Blaster Mk II</i>, has been responsible for devastating military outposts.</p><p>Below is a map showing Zorak known territories and threat levels:</p><div class='map-container' style='position: relative; display: inline-block; width: 600px; height: 600px;'><img src='/static/images/map.webp' alt='Galaxy Map' width='600' height='600'><div class='marker' style='position: absolute; top: 10%; left: 15%;'><svg xmlns='http://www.w3.org/2000/svg' xml:space='preserve' width='30' height='30' style='shape-rendering:geometricPrecision;text-rendering:geometricPrecision;image-rendering:optimizeQuality;fill-rule:evenodd;clip-rule:evenodd' viewBox='0 0 6.827 6.827'><defs><style>.fil1{fill:none}</style></defs><g id='Layer_x0020_1'><path d='M4.304 2.189a.89.89 0 1 0-1.781 0 .89.89 0 0 0 1.78 0z' style='fill:#64ffda'/><path class='fil1' d='M0 0h6.827v6.827H0z'/><path class='fil1' d='M.853.853h5.12v5.12H.853z'/><path d='M3.413.853c.776 0 1.405.585 1.405 1.305 0 .485-1.164 3.18-1.405 3.815-.17-.447-1.405-3.298-1.405-3.815 0-.72.63-1.305 1.405-1.305zm0 .446a.89.89 0 1 1 0 1.78.89.89 0 0 1 0-1.78z' style='fill:#26a69a'/></g></svg></div><div class='marker' style='position: absolute; top: 30%; left: 50%;'><svg xmlns='http://www.w3.org/2000/svg' xml:space='preserve' width='30' height='30' style='shape-rendering:geometricPrecision;text-rendering:geometricPrecision;image-rendering:optimizeQuality;fill-rule:evenodd;clip-rule:evenodd' viewBox='0 0 6.827 6.827'><defs><style>.fil1{fill:none}</style></defs><g id='Layer_x0020_1'><path d='M4.304 2.189a.89.89 0 1 0-1.781 0 .89.89 0 0 0 1.78 0z' style='fill:#64ffda'/><path class='fil1' d='M0 0h6.827v6.827H0z'/><path class='fil1' d='M.853.853h5.12v5.12H.853z'/><path d='M3.413.853c.776 0 1.405.585 1.405 1.305 0 .485-1.164 3.18-1.405 3.815-.17-.447-1.405-3.298-1.405-3.815 0-.72.63-1.305 1.405-1.305zm0 .446a.89.89 0 1 1 0 1.78.89.89 0 0 1 0-1.78z' style='fill:#26a69a'/></g></svg></div><div class='marker' style='position: absolute; top: 50%; left: 70%;'><svg xmlns='http://www.w3.org/2000/svg' xml:space='preserve' width='30' height='30' style='shape-rendering:geometricPrecision;text-rendering:geometricPrecision;image-rendering:optimizeQuality;fill-rule:evenodd;clip-rule:evenodd' viewBox='0 0 6.827 6.827'><defs><style>.fil1{fill:none}</style></defs><g id='Layer_x0020_1'><path d='M4.304 2.189a.89.89 0 1 0-1.781 0 .89.89 0 0 0 1.78 0z' style='fill:#64ffda'/><path class='fil1' d='M0 0h6.827v6.827H0z'/><path class='fil1' d='M.853.853h5.12v5.12H.853z'/><path d='M3.413.853c.776 0 1.405.585 1.405 1.305 0 .485-1.164 3.18-1.405 3.815-.17-.447-1.405-3.298-1.405-3.815 0-.72.63-1.305 1.405-1.305zm0 .446a.89.89 0 1 1 0 1.78.89.89 0 0 1 0-1.78z' style='fill:#26a69a'/></g></svg></div><div class='marker' style='position: absolute; top: 50%; left: 50%;'><svg xmlns='http://www.w3.org/2000/svg' xml:space='preserve' width='30' height='30' style='shape-rendering:geometricPrecision;text-rendering:geometricPrecision;image-rendering:optimizeQuality;fill-rule:evenodd;clip-rule:evenodd' viewBox='0 0 6.827 6.827'><defs><style>.fil1{fill:none}</style></defs><g id='Layer_x0020_1'><path d='M4.304 2.189a.89.89 0 1 0-1.781 0 .89.89 0 0 0 1.78 0z' style='fill:#64ffda'/><path class='fil1' d='M0 0h6.827v6.827H0z'/><path class='fil1' d='M.853.853h5.12v5.12H.853z'/><path d='M3.413.853c.776 0 1.405.585 1.405 1.305 0 .485-1.164 3.18-1.405 3.815-.17-.447-1.405-3.298-1.405-3.815 0-.72.63-1.305 1.405-1.305zm0 .446a.89.89 0 1 1 0 1.78.89.89 0 0 1 0-1.78z' style='fill:#26a69a'/></g></svg></div><div class='marker' style='position: absolute; top: 50%; left: 40%;'><svg xmlns='http://www.w3.org/2000/svg' xml:space='preserve' width='30' height='30' style='shape-rendering:geometricPrecision;text-rendering:geometricPrecision;image-rendering:optimizeQuality;fill-rule:evenodd;clip-rule:evenodd' viewBox='0 0 6.827 6.827'><defs><style>.fil1{fill:none}</style></defs><g id='Layer_x0020_1'><path d='M4.304 2.189a.89.89 0 1 0-1.781 0 .89.89 0 0 0 1.78 0z' style='fill:#64ffda'/><path class='fil1' d='M0 0h6.827v6.827H0z'/><path class='fil1' d='M.853.853h5.12v5.12H.853z'/><path d='M3.413.853c.776 0 1.405.585 1.405 1.305 0 .485-1.164 3.18-1.405 3.815-.17-.447-1.405-3.298-1.405-3.815 0-.72.63-1.305 1.405-1.305zm0 .446a.89.89 0 1 1 0 1.78.89.89 0 0 1 0-1.78z' style='fill:#26a69a'/></g></svg></div></div><p>The custom markers in the graphic represent the <em>threat level</em> of Zorak known territories. Consider extreme caution when approaching these areas.</p>",
        },
        {
          target_name: "Jax Colt",
          target_aliases: "The Lone Wolf, Ghost of the Frontier",
          target_species: "Human",
          last_known_location: "Frontier Station Alpha",
          galaxy: "Milky Way",
          star_system: "Sol",
          planet: "Earth",
          coordinates: "0.00, 0.00, 0.00",
          crimes:
            "Disruption of supply routes, Tactical espionage, Guerrilla warfare",
          reward_credits: 75000.0,
          reward_items: "Frontier Ship Engine Upgrade",
          issuer_name: "Xclow3n",
          issuer_faction: "Alliance",
          risk_level: "medium",
          required_equipment: "Disguise Kit, Holo Shield",
          posted_at: "2024-08-21",
          status: "open",
          image: "/static/images/JaxC.png",
          description:
            "<p><strong>Jax Colt</strong> has evaded capture for years. Known for his expertise in guerrilla tactics, his operations disrupt major supply routes across the Milky Way.</p><p>At each of his crime scenes, Colt leaves behind a cryptic note, often involving complex mathematical symbols:</p><math xmlns='http://www.w3.org/1998/Math/MathML'><mo>∇</mo> • <mi>S</mi>(<mi>t</mi>) + ∫ (𝜕𝑉/𝜕𝑥)𝑑𝑥 = Φ(𝑡₀) where 𝜓 = det(H(𝑥)) as t → ∞</math><p>Authorities have yet to decode the meaning of these symbols, but it is believed they hint at Colt’s next move. Capture or kill recommended. Extreme caution is advised.</p>",
        },
        {
          target_name: "Mara Dune",
          target_aliases: "The Shadow Dancer",
          target_species: "Twilek",
          last_known_location: "Korriban",
          galaxy: "Outer Rim",
          star_system: "Tatooine",
          planet: "Tatooine",
          coordinates: "145.23, 456.44, 321.78",
          crimes: "Espionage, Stealth infiltration, High-profile assassination",
          reward_credits: 40000.0,
          reward_items: "Advanced Stealth Suit",
          issuer_name: "Xclow3n",
          issuer_faction: "Guild",
          risk_level: "high",
          required_equipment: "Thermal Detonators, Cloaking Device",
          posted_at: "2024-09-10",
          status: "claimed",
          image: "/static/images/Sara.png",
          description:
            "<p><strong>Mara Dune</strong> has earned the nickname 'The Shadow Dancer' due to her agility and proficiency in stealth combat. Her last known location was deep in the <em>Tatooine desert</em>, where she believed to be gathering intelligence.</p><p>Proceed with extreme caution. </p>",
        },
        {
          target_name: "Drexor the Insane",
          target_aliases: "Madman of Zeta",
          target_species: "Zetarian",
          last_known_location: "Zeta Prime",
          galaxy: "Andromeda",
          star_system: "Zeta Cluster",
          planet: "Zeta Prime",
          coordinates: "328.12, 178.45, 92.66",
          crimes: "Mass destruction, Terrorism, High-speed chase",
          reward_credits: 60000.0,
          reward_items: "Personal Shield Generator, Rare Crystals",
          issuer_name: "Xclow3n",
          issuer_faction: "Corporation",
          risk_level: "high",
          required_equipment: "EMP Disruptor, Force Field",
          posted_at: "2024-07-10",
          status: "closed",
          image: "/static/images/Drex.png",
          description:
            "<p><strong>Drexor the Insane</strong>, known for his erratic behavior, was finally captured after a high-speed chase. His tactical defenses often included <i>personal shield generators</i>, and his ship was equipped with a powerful <i>Force Field</i>.</p><p>The figure below illustrates the probable structure of his defensive system:</p><img src='/static/images/defense.webp' style='position: relative; display: inline-block; width: 600px; height: 600px;' />",
        },
        {
          target_name: "Kalus Varr",
          target_aliases: "Death from the Shadows",
          target_species: "Rodian",
          last_known_location: "Nar Shaddaa",
          galaxy: "Hutt Space",
          star_system: "Nar Shaddaa System",
          planet: "Nar Shaddaa",
          coordinates: "200.32, 400.18, 77.55",
          crimes: "Assassination, Smuggling, Political destabilization",
          reward_credits: 45000.0,
          reward_items: "Black Market Credits, Advanced Blaster Pistol",
          issuer_name: "Xclow3n",
          issuer_faction: "Syndicate",
          risk_level: "medium",
          required_equipment: "Hacking Tools, Stealth Field Generator",
          posted_at: "2024-09-05",
          status: "claimed",
          image: "/static/images/Kalu.png",
          description:
            "<div class='bounty-description'><p><strong>Kalus Varr</strong> is a Rodian feared for his near-flawless precision in eliminating high-profile targets. His skills in assassination have destabilized political regimes and sown chaos across the Nar Shaddaa system. Operating from the shadows, he is suspected of being backed by a powerful and secretive crime syndicate. The Syndicate’s influence spans entire star systems, and their operations are as covert as they are deadly.</p><p>Kalus often leaves cryptic symbols at the scenes of his assassinations, sending a chilling message to his enemies. These symbols are believed to represent key Syndicate hubs, with each marking an area of their influence.</p><p>His last known activities suggest he orchestrating a series of high-profile political assassinations, and his next target could be anyone in power. Approach with extreme caution; anyone connected to the Syndicate vanishes without a trace.</p><div class='symbol-image'><img src='/static/images/py.webp' alt='Kalus Varr Symbol' width='300' height='300'></div></div><style>.symbol-image {margin-top: 20px;text-align: center;} .symbol-image img {border-radius: 5px;opacity: 0.85;}</style>",
        },
        {
          target_name: "Sarakon the Deceiver",
          target_aliases: "Master of Disguise",
          target_species: "Human",
          last_known_location: "Coruscant",
          galaxy: "Core Worlds",
          star_system: "Coruscant System",
          planet: "Coruscant",
          coordinates: "67.45, 128.98, 78.23",
          crimes: "Impersonation, Fraud, High-profile theft",
          reward_credits: 30000.0,
          reward_items: "Stolen Artifacts, Gemstones",
          issuer_name: "Xclow3n",
          issuer_faction: "Republic",
          risk_level: "medium",
          required_equipment: "Disguise Kit, Surveillance Gear",
          posted_at: "2024-06-30",
          status: "closed",
          image: "/static/images/Mara.png",
          description:
            "<p><strong>Sarakon the Deceiver</strong> was captured while attempting to impersonate a Republic senator. His skills in disguise and misdirection made him a high-value target.</p><p>The following is a representation of the intricate network he built to remain undetected:</p><img src='/static/images/net.webp' alt='Network Diagram' width='400' height='400' /><p>This network is believed to be a mix of bribery, false identities, and encrypted communication channels used to carry out high-profile impersonations across the galaxy.</p>",
        },
      ]);

      console.log("Predefined bounties have been inserted.");
    } catch (error) {
      console.error("Error migrating the database:", error);
    }
  }
}

module.exports = new Database();
