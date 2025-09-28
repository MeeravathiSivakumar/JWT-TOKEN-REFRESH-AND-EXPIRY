const express = require("express");
const jwt = require("jsonwebtoken");
const bodyParser = require("body-parser");

const app = express();
app.use(bodyParser.json());

const ACCESS_SECRET = "super_secret_access";
const REFRESH_SECRET = "super_secret_refresh";

let refreshTokens = []; // Local state storage

// Generate tokens
function generateAccessToken(user) {
  return jwt.sign(user, ACCESS_SECRET, { expiresIn: "15m" });
}
function generateRefreshToken(user) {
  const token = jwt.sign(user, REFRESH_SECRET, { expiresIn: "7d" });
  refreshTokens.push(token); // Store in memory
  return token;
}

// Login
app.post("/login", (req, res) => {
  const { username } = req.body;
  const user = { username };
  const accessToken = generateAccessToken(user);
  const refreshToken = generateRefreshToken(user);
  res.json({ accessToken, refreshToken });
});

// Refresh
app.post("/refresh", (req, res) => {
  const { token } = req.body;
  if (!token || !refreshTokens.includes(token))
    return res.sendStatus(403);

  jwt.verify(token, REFRESH_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    const accessToken = generateAccessToken({ username: user.username });
    res.json({ accessToken });
  });
});

// Logout – delete refresh token
app.post("/logout", (req, res) => {
  const { token } = req.body;
  refreshTokens = refreshTokens.filter(t => t !== token);
  res.sendStatus(204);
});

app.listen(4000, () => console.log("Server running on port 4000 (Memory mode)"));
