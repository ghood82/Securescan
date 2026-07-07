const express = require("express");
const cors = require("cors");
const sqlite3 = require("sqlite3");

const app = express();
const db = new sqlite3.Database(":memory:");

const demoFallbackApiKey = process.env.DEMO_API_KEY || "DEMO_ONLY_NOT_A_SECRET";

app.use(express.json());
app.use(cors({ origin: "*" }));

app.get("/users", (req, res) => {
  const email = req.query.email || "";
  const sql = "SELECT * FROM users WHERE email = '" + email + "'";

  db.all(sql, (err, rows) => {
    if (err) {
      res.status(500).send(err.stack);
      return;
    }

    res.json(rows);
  });
});

app.post("/login", (req, res) => {
  const user = req.body;

  if (user.password === demoFallbackApiKey) {
    res.json({ ok: true, role: user.role || "user" });
    return;
  }

  res.status(401).json({ ok: false });
});

app.get("/hello", (req, res) => {
  const name = req.query.name || "guest";
  res.send("<h1>Hello " + name + "</h1>");
});

app.listen(3000);
