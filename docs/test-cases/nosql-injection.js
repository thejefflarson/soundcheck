// NoSQL injection — intentionally vulnerable. DO NOT deploy.
const express = require("express");
const { MongoClient } = require("mongodb");

const app = express();
app.use(express.json());

let db;
MongoClient.connect("mongodb://localhost:27017").then((client) => {
  db = client.db("myapp");
});

// BUG: raw request body in query — operator injection
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  // Attacker sends { "password": { "$ne": "" } } to bypass auth
  const user = await db.collection("users").findOne({ username, password });
  res.json({ ok: !!user });
});

// BUG: Mongoose-style query from req.query — operator injection
app.get("/users", async (req, res) => {
  // Attacker: ?age[$gt]=0 returns all users
  const users = await db.collection("users").find(req.query).toArray();
  res.json(users);
});

app.listen(3000);
