// routes.js
const express = require("express");
const jwt = require("jsonwebtoken");
const passport = require("passport");
const { updateUserRefreshToken, findUserById, findUserByEmail, createUser } = require("./userModel");
const router = express.Router();

const SECRET_KEY = "your_secret_key";
const REFRESH_SECRET_KEY = "your_refresh_secret_key";

// Register route
router.post("/register", async (req, res) => {
  const { email, password, role } = req.body;

  if (!email || !password || !role) {
    return res
      .status(400)
      .json({ message: "Email, password, and role are required" });
  }

  if (!["admin", "general"].includes(role)) {
    return res.status(400).json({ message: "Invalid role specified" });
  }

  try {
    // Check if the email already exists
    const existingUser = await findUserByEmail(email);
    if (existingUser) {
      return res.status(400).json({ message: "Email already in use" });
    }

    // Create the new user
    const userId = await createUser(email, password, role);

    res.status(201).json({ message: "User registered successfully", userId });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Login route
router.post("/login", (req, res, next) => {
  passport.authenticate(
    "local",
    { session: false },
    async (err, user, info) => {
      if (err) return next(err);
      if (!user)
        return res.status(401).json({ message: "Invalid credentials" });

      const token = jwt.sign({ id: user.id, role: user.role }, SECRET_KEY, {
        expiresIn: "15m",
      });
      const refreshToken = jwt.sign({ id: user.id }, REFRESH_SECRET_KEY, {
        expiresIn: "7d",
      });

      // Store the refresh token in the database
      await updateUserRefreshToken(user.id, refreshToken);

      // Set the tokens as cookies
      res.cookie("token", token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
      });
      res.cookie("refreshToken", refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        path: "/api/refresh-token",
      });

      res.json({ message: "Logged in successfully" });
    }
  )(req, res, next);
});

// Refresh token route
router.post("/refresh-token", async (req, res) => {
  const refreshToken = req.cookies.refreshToken;
  if (!refreshToken)
    return res.status(401).json({ message: "Refresh Token not provided" });

  jwt.verify(refreshToken, REFRESH_SECRET_KEY, async (err, decoded) => {
    if (err) return res.status(403).json({ message: "Invalid Refresh Token" });

    const user = await findUserById(decoded.id);
    if (!user || user.refreshToken !== refreshToken) {
      return res.status(403).json({ message: "Invalid Refresh Token" });
    }

    const newAccessToken = jwt.sign(
      { id: user.id, role: user.role },
      SECRET_KEY,
      { expiresIn: "15m" }
    );

    res.cookie("token", newAccessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
    });

    res.json({ message: "Access token refreshed" });
  });
});

router.post("/logout", async (req, res) => {
  const user = await findUserById(req.user.id);
  if (user) {
    await updateUserRefreshToken(user.id, null);
  }
  res.clearCookie("token");
  res.clearCookie("refreshToken");
  res.json({ message: "Logged out successfully" });
});

module.exports = router;
