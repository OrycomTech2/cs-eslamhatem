// routes/searchRoutes.js
const express = require("express");
const router = express.Router();
const User = require("../models/User");
const Admin = require("../models/Admin");
const Instructor = require("../models/Instructor");

router.get("/search", async (req, res) => {
  try {
    const q = req.query.q || "";

    const users = await User.find({ name: new RegExp(q, "i") }).select("name _id");
    const instructors = await Instructor.find({ name: new RegExp(q, "i") }).select("name _id");
    const admins = await Admin.find({ username: new RegExp(q, "i") }).select("username _id");

    const results = [
      ...users.map(u => ({ id: u._id, label: u.name, type: "user" })),
      ...instructors.map(i => ({ id: i._id, label: i.name, type: "instructor" })),
      ...admins.map(a => ({ id: a._id, label: a.username, type: "admin" }))
    ];

    res.json(results); // always array
  } catch (err) {
    console.error("Search error:", err.message);
    res.status(500).json({ error: "Server error" });
  }
});

module.exports = router;
