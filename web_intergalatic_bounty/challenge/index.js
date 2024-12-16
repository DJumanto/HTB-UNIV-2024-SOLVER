const express = require("express");
const cookieParser = require("cookie-parser");
const routes = require("./routes");
const nunjucks = require("nunjucks");
const path = require("path");
const db = require("./database");

const app = express();
app.use(express.json());
app.use(cookieParser());

nunjucks.configure("views", {
  autoescape: true,
  express: app,
});

app.use("/static", express.static(path.join(__dirname, "static")));
app.set("view engine", "html");

app.use(routes);

(async () => {
  await db.connect();
  await db.migrate();
})();

(async () => {
	app.listen(1337, '0.0.0.0', () => console.log('Listening on port 1337'));
})();