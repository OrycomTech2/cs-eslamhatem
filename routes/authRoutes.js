const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const path = require("path");
const upload = require("../middleware/upload");
const { authMiddleware } = require("../middleware/authMiddleware");
const User = require("../models/User");
const authController = require("../controllers/authController");
const router = express.Router();

// Register
router.post("/register", authController.register);

// Login
router.post("/login", authController.login);

/**
 * GET /api/auth/me
 * Header: Authorization: Bearer <token>
 */
router.get("/me", authMiddleware, async (req, res) => {
  try {
    const me = await User.findById(req.user.userId).select("-password");
    if (!me) return res.status(404).json({ message: "User not found" });
    return res.json({ user: me });
  } catch {
    return res.status(500).json({ message: "Failed to load profile" });
  }
});

/**
 * GET /api/auth/room-token
 * For live sessions (Socket/Peer helpers)
 */
router.get("/room-token", authMiddleware, (req, res) => {
  try {
    const payload = {
      sessionId: `session-${Date.now()}`,
      userId: req.user.userId,
      role: req.user.role || "student",
    };
    const roomToken = jwt.sign(payload, process.env.ROOM_TOKEN_SECRET, { expiresIn: "1h" });
    return res.json({ roomToken });
  } catch (err) {
    console.error("Room token error:", err);
    return res.status(500).json({ message: "Failed to issue room token" });
  }
});

module.exports = router;
