require("dotenv").config();
const app = require("./app");
const { mongoConnect } = require("./src/db/database");

const required = require("./utils/requireEnvVar")

const PORT = required("SERVER_PORT") || 3000;

// ^ setting up MongoDB connection
mongoConnect(() => {
  app.listen(PORT);
});
