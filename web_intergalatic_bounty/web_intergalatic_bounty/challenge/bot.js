const puppeteer = require("puppeteer");
const User = require("./models/userModel");
const { createToken } = require("./util");

const visitReport = async (id) => {
  const browser = await puppeteer.launch({
    headless: true,
    args: ["--no-sandbox", "--disable-setuid-sandbox"],
  });

  const page = await browser.newPage();

  await page.setCookie({
    name: "auth",
    value: createToken(await User.getUserByEmail("admin@interstellar.htb")),
    domain: "127.0.0.1",
  });

  const url = `http://127.0.0.1:1337/bounty/${id}`;

  try {
    await page.goto(url, {
      waitUntil: "networkidle0",
    });

    console.log(`Visited: ${url}`);

    const content = await page.content();
  } catch (err) {
    console.error("Error visiting the page:", err);
  } finally {
    await browser.close();
  }
};

module.exports = { visitReport };