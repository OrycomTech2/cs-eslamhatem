// controllers/liveController.js
const LiveTask = require('../models/LiveTask');
const Course = require('../models/Course');
const LiveSession = require("../models/LiveSession");
const jwt = require("jsonwebtoken");
const User = require("../models/User");

exports.getUserLiveSessions = async (req, res) => {
  console.log("✅ Hit /my-live-sessions route");

  try {
    console.log("🔍 req.user =", req.user);

    if (!req.user) {
      console.log("❌ req.user is undefined — authentication failed.");
      return res.status(401).json({ message: "Not authenticated" });
    }

    // ✅ FIX: correct field name
    const userId = req.user.userId;
    console.log("✅ Extracted userId =", userId);

    console.log("🔍 Looking up user in DB...");
    const user = await User.findById(userId).populate("paidCourses");

    console.log("✅ DB user =", user);

    if (!user) {
      console.log("❌ User not found in DB");
      return res.status(404).json({ message: "User not found" });
    }

    console.log("✅ User paidCourses =", user.paidCourses);

    console.log("🔍 Finding sessions...");
    const sessions = await LiveSession.find({
      course: { $in: user.paidCourses }
    }).populate("course");

    console.log("✅ Found sessions =", sessions);

    return res.json({ sessions });

  } catch (err) {
    console.log("❌ ERROR in getUserLiveSessions()");
    console.error(err);

    return res.status(500).json({
      message: "Server error",
      error: err.message,
      stack: err.stack
    });
  }
};
// Start live session
exports.startSession = async (req, res) => {
  try {
    const { courseId } = req.body;

    // Validate course exists
    const course = await Course.findById(courseId);
    if (!course) {
      return res.status(404).json({ success: false, message: "Course not found" });
    }

    // Create new live session
    const newSession = await LiveSession.create({
      course: courseId,
      instructor: req.user._id, // now using _id from auth
      startTime: new Date(),
      active: true
    });

    res.status(201).json({
      success: true,
      sessionId: newSession._id,
      message: "Live session started"
    });
  } catch (err) {
    console.error("Error starting live session:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
};

// End live session
exports.endLiveSession = async (req, res) => {
  try {
    const { sessionId } = req.params;
    const session = await LiveSession.findById(sessionId);

    if (!session) {
      return res.status(404).json({ message: "Live session not found" });
    }

    if (session.instructor.toString() !== req.user._id.toString()) {
      return res.status(403).json({ message: "Not authorized to end this session" });
    }

    session.active = false; // consistent naming
    session.endTime = new Date();
    await session.save();

    res.json({ success: true, message: "Live session ended" });
  } catch (error) {
    console.error("Error ending live session:", error);
    res.status(500).json({ message: "Server error" });
  }
};

// Send task/question to students
exports.sendLiveTask = async (req, res) => {
  try {
    const { sessionId, question } = req.body;

    const session = await LiveSession.findById(sessionId);
    if (!session) {
      return res.status(404).json({ message: "Live session not found" });
    }

    if (session.instructor.toString() !== req.user._id.toString()) {
      return res.status(403).json({ message: "Not authorized to send tasks" });
    }

    const task = await LiveTask.create({ session: sessionId, question });

    // Emit to connected students in this session room
    if (req.io) {
      req.io.to(sessionId).emit('newTask', task);
    }

    res.status(201).json({ success: true, message: "Task sent", task });
  } catch (error) {
    console.error("Error sending live task:", error);
    res.status(500).json({ message: "Server error" });
  }
};

// Generate short-lived join token for students
exports.requestJoinToken = async (req, res) => {
  try {
    const { courseId, sessionId } = req.body;
    const userId = req.user._id;

    // Check if course exists
    const course = await Course.findById(courseId);
    if (!course) {
      return res.status(404).json({ error: "Course not found" });
    }

    // Verify student enrollment
    if (!course.enrolledStudents.includes(userId)) {
      return res.status(403).json({ error: "You are not enrolled in this course" });
    }

    // Check if session exists and is active
    const session = await LiveSession.findById(sessionId);
    if (!session || !session.active) {
      return res.status(404).json({ error: "Live session not found or inactive" });
    }

    // Create short-lived token
    const token = jwt.sign(
      { sessionId, userId },
      process.env.LIVE_SESSION_SECRET,
      { expiresIn: "5m" }
    );

    res.json({ success: true, token });
  } catch (err) {
    console.error("Error generating join token:", err);
    res.status(500).json({ error: "Internal server error" });
  }
};
