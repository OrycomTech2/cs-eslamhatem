// controllers/taskSubmissionController.js
const TaskSubmission = require("../models/TaskSubmission");

// Instructor reviews submission
exports.reviewSubmission = async (req, res) => {
  try {
    const { submissionId } = req.params;
    const { feedback } = req.body;

    const submission = await TaskSubmission.findByIdAndUpdate(
      submissionId,
      { feedback, status: "reviewed" },
      { new: true }
    )
      .populate("student", "name email")
      .populate("course", "title");

    if (!submission) {
      return res.status(404).json({ error: "Submission not found" });
    }

    res.json({ message: "✅ Submission reviewed", submission });
  } catch (err) {
    console.error("Error reviewing submission:", err);
    res.status(500).json({ error: "Server error" });
  }
};
