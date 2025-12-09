const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const User = require("../models/User");
const Assignment = require("../models/Assignment");
const Submission = require("../models/Submission");
const Quiz = require("../models/Quiz");
const QuizAttempt = require("../models/QuizAttempt");
const LiveSession = require("../models/LiveSession");
const Assistant = require ("../models/Assistant");
const Course = require("../models/Course");
/* ========================
   🔑 Assistant Login
======================== */
exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;
    console.log("🟢 Login attempt for email:", email);

    const assistant = await Assistant.findOne({ email }); // search in Assistant collection
    if (!assistant) {
      console.log("❌ Assistant not found for email:", email);
      return res.status(401).json({ message: "Not authorized" });
    }
    console.log("✅ Assistant found:", assistant.email, "Role:", assistant.role);

    const isMatch = await bcrypt.compare(password, assistant.password);
    console.log("🔑 Password comparison result:", isMatch);

    if (!isMatch) {
      console.log("❌ Password mismatch for assistant:", email);
      return res.status(401).json({ message: "Invalid credentials" });
    }

    console.log("✅ Password matched, generating JWT...");

    const token = jwt.sign(
      { userId: assistant._id, role: assistant.role },
      process.env.JWT_SECRET,
      { expiresIn: "1d" }
    );

    const { password: pwd, ...assistantData } = assistant.toObject();
    console.log("✅ JWT generated successfully for:", email);

    res.json({ token, assistant: assistantData });
  } catch (err) {
    console.error("❌ Assistant login error:", err);
    res.status(500).json({ message: "Server error", error: err.message });
  }
};


/* ========================
   👤 Profile
======================== */
exports.getProfile = async (req, res) => {
  try {
    const assistant = await Assistant.findById(req.user.userId).select("-password");
    if (!assistant) {
      return res.status(404).json({ message: "Assistant not found" });
    }
    res.json({ assistant });
  } catch (err) {
    console.error("Get assistant profile error:", err);
    res.status(500).json({ message: "Server error" });
  }
};

exports.updateProfile = async (req, res) => {
  try {
    const { name, phoneNumber } = req.body;
const photo = req.file ? `/uploads/profile/${req.file.filename}` : undefined;

    const updatedAssistant = await Assistant.findByIdAndUpdate(
      req.user.userId,
      { $set: { name, phoneNumber, ...(photo && { photo }) } },
      { new: true }
    ).select("-password");

    res.json({ assistant: updatedAssistant });
  } catch (err) {
    console.error("Update assistant profile error:", err);
    res.status(500).json({ message: "Server error" });
  }
};

// Controller for Assistant: See all active live sessions
exports.getAvailableLiveSessions = async (req, res) => {
  try {
    const assistantId = req.user.userId;
    const assistant = await Assistant.findById(assistantId).populate("assignedCourses", "title _id type");

    if (!assistant) return res.status(404).json({ message: "Assistant not found" });

    const activeRooms = req.app.get("activeRooms") || {};
    const availableSessions = [];

    for (const [roomId, roomData] of Object.entries(activeRooms)) {
      const isEnrolled = assistant.assignedCourses.some(
        course => course._id.toString() === roomData.courseId
      );

      if (isEnrolled) {
        const course = assistant.assignedCourses.find(c => c._id.toString() === roomData.courseId);

        availableSessions.push({
          roomId,
          courseId: roomData.courseId,
          courseTitle: course?.title || "Unknown Course",
          instructorName: "Islam Hatem", // single-teacher site
          studentCount: Object.keys(roomData.students || {}).length,
          startedAt: roomData.createdAt
        });
      }
    }

    res.status(200).json({ data: availableSessions });
  } catch (err) {
    console.error("Error fetching live sessions:", err);
    res.status(500).json({ message: "Error fetching live sessions", error: err.message });
  }
};


exports.changePassword = async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    const assistant = await Assistant.findById(req.user.userId);
    if (!assistant) return res.status(404).json({ message: "Assistant not found" });

    const isMatch = await bcrypt.compare(currentPassword, assistant.password);
    if (!isMatch) return res.status(400).json({ message: "Incorrect current password" });

    assistant.password = await bcrypt.hash(newPassword, 10);
    await assistant.save();

    res.json({ message: "Password updated successfully" });
  } catch (err) {
    console.error("Change password error:", err);
    res.status(500).json({ message: "Server error" });
  }
};

/* ========================
   📝 Assignments
======================== */
exports.createAssignment = async (req, res) => {
  try {
    const { title, description, courseId, dueDate } = req.body;
    const assignment = new Assignment({ title, description, course: courseId, dueDate });
    await assignment.save();
    res.json({ success: true, data: assignment });
  } catch (err) {
    console.error("Create assignment error:", err);
    res.status(500).json({ error: "Server error" });
  }
};

exports.listSubmissions = async (req, res) => {
  try {
    const submissions = await Submission.find()
      .populate("student", "name email")
      .populate("assignment", "title");
    res.json({ success: true, data: submissions });
  } catch (err) {
    console.error("List submissions error:", err);
    res.status(500).json({ error: "Server error" });
  }
};
exports.updateAssignment = async (req, res) => {
  try {
    const { id } = req.params;
    const { title, description, dueDate } = req.body;
    const updateData = { title, description, dueDate };

    if (req.file) {
      updateData.pdf = req.file.filename; // save uploaded file
    }

    const assignment = await Assignment.findByIdAndUpdate(id, updateData, { new: true });
    if (!assignment) return res.status(404).json({ error: "Assignment not found" });

    res.json({ success: true, data: assignment });
  } catch (err) {
    console.error("Update assignment error:", err);
    res.status(500).json({ error: "Server error" });
  }
};


exports.deleteAssignment = async (req, res) => {
  try {
    await Assignment.findByIdAndDelete(req.params.id);
    res.json({ message: "Assignment deleted" });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
};

exports.listAssignments = async (req, res) => {
  try {
    const assignments = await Assignment.find().populate("course", "title");
    res.json({ data: assignments });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
};

exports.reviewSubmission = async (req, res) => {
  try {
    const { id } = req.params;
    const { feedback, grade } = req.body;
    const submission = await Submission.findById(id);
    if (!submission) return res.status(404).json({ error: "Submission not found" });

    submission.feedback = feedback || submission.feedback;
    submission.grade = grade || submission.grade;
    submission.reviewedBy = req.user.userId;
    submission.reviewedAt = new Date();
    await submission.save();

    res.json({ success: true, data: submission });
  } catch (err) {
    console.error("Review submission error:", err);
    res.status(500).json({ error: "Server error" });
  }
};


/* ========================
  course fetch   
======================== */
exports.getCourses = async (req, res) => {
  try {
    const courses = await Course.find().select("title description price type thumbnail");
    res.json({ success: true, data: courses });
  } catch (err) {
    console.error("Get courses error:", err);
    res.status(500).json({ error: "Server error" });
  }
};
/* ========================
   ❓ Quizzes
======================== */
exports.createQuiz = async (req, res) => {
  try {
    const { title, questions, courseId } = req.body;
    const quiz = new Quiz({ title, questions, course: courseId });
    await quiz.save();
    res.json({ success: true, data: quiz });
  } catch (err) {
    console.error("Create quiz error:", err);
    res.status(500).json({ error: "Server error" });
  }
};

exports.listQuizSubmissions = async (req, res) => {
  try {
    const submissions = await QuizAttempt.find()
      .populate("student", "name email")
      .populate("quiz", "title");
    res.json({ success: true, data: submissions });
  } catch (err) {
    console.error("List quiz submissions error:", err);
    res.status(500).json({ error: "Server error" });
  }
};

/* ========================
   🎥 Live Sessions (view-only)
======================== */
exports.listLiveSessions = async (req, res) => {
  try {
    const sessions = await LiveSession.find().populate("course", "title");
    res.json({ success: true, data: sessions });
  } catch (err) {
    console.error("List live sessions error:", err);
    res.status(500).json({ error: "Server error" });
  }
};
