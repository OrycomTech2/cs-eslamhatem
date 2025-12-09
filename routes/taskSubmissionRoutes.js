// routes/taskSubmissionRoutes.js
const express = require("express");
const router = express.Router();
const TaskSubmission = require("../models/TaskSubmission");
const authMiddleware = require("../middleware/auth");
const taskSubmissionController = require("../controllers/taskSubmissionController");
const allowAdminOrAssistant = require("../middleware/authAdminOrAssistant");


// Student submits task outside live session
router.post("/", authMiddleware, async (req, res) => {
  try {
    const { content, fileUrl, taskId, courseId } = req.body;
    const submission = new TaskSubmission({
      student: req.user.userId,
      content,
      fileUrl,
      task: taskId || null,
      course: courseId || null
    });
    await submission.save();
    res.json({ message: "✅ Submission saved", submission });
  } catch (err) {
    console.error("Error saving submission:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Instructor fetches submissions
router.get("/", authMiddleware, async (req, res) => {
  try {
    const submissions = await TaskSubmission.find()
      .populate("student", "name email")
      .populate("course", "title");
    res.json(submissions);
  } catch (err) {
    console.error("Error fetching submissions:", err);
    res.status(500).json({ error: "Server error" });
  }
});
router.patch("/:submissionId/review", allowAdminOrAssistant, taskSubmissionController.reviewSubmission);

module.exports = router;
