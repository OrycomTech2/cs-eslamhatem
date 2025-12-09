const express = require("express");
const router = express.Router();
const jwt = require("jsonwebtoken");
const Instructor = require("../models/Instructor");
const bcrypt = require("bcryptjs");

function generateToken(id) {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: "7d",
  });
}

// REGISTER
router.post("/register", async (req, res) => {
  console.log("✅ Received instructor register request:", req.body);

  try {
    const { name, email, password, bio, subjects } = req.body;

    // Basic validation
    if (!name || !email || !password) {
      return res.status(400).json({ message: "Name, email, and password are required" });
    }

    // Check if email already exists
    const existing = await Instructor.findOne({ email });
    if (existing) {
      return res.status(400).json({ message: "Email already exists" });
    }

    // Hash password before saving
    const hashedPassword = await bcrypt.hash(password, 10);

    const instructor = new Instructor({
      name,
      email,
      password: hashedPassword,
      bio,
      courses
    });

    await instructor.save();

    const token = generateToken(instructor._id);

    // Remove password before sending
    const { password: pwd, ...safeInstructor } = instructor.toObject();

    res.status(201).json({
      token,
      role: "instructor",
      instructorId: instructor._id,
       modelType: 'Instructor',
      instructor: safeInstructor
    });
  } catch (err) {
    console.error("❌ Registration error:", err);
    res.status(500).json({ message: err.message || "Error registering instructor" });
  }
});

// LOGIN
router.post("/login", async (req, res) => {
  console.log("✅ Received instructor login request:", req.body);

  try {
    const { email, password } = req.body;

    const instructor = await Instructor.findOne({ email });
    if (!instructor) {
      return res.status(401).json({ message: "Invalid email or password" });
    }

    const isMatch = await bcrypt.compare(password, instructor.password);
    if (!isMatch) {
      return res.status(401).json({ message: "Invalid email or password" });
    }

    const token = generateToken(instructor._id);

    // Remove password before sending
    const { password: pwd, ...safeInstructor } = instructor.toObject();

    res.status(200).json({
      token,
      role: "instructor",
      instructorId: instructor._id,
       modelType: 'Instructor',
       instructor: safeInstructor
    });
  } catch (err) {
    console.error("❌ Login error:", err);
    res.status(500).json({ message: err.message || "Login failed" });
  }
});

module.exports = router;
