const express = require("express");
const router = express.Router();
const Task = require("../models/Task");
const TaskSubmission = require("../models/TaskSubmission");
const auth = require("../middleware/auth"); // middleware to decode JWT

/* ================
   TASK MANAGEMENT
================ */
router.post("/", auth, async (req, res) => {
  try {
    const { title, description, course, dueDate } = req.body;
    const task = new Task({
      title,
      description,
      course,
      dueDate,
      createdBy: req.user.userId
    });
    await task.save();
    res.json({ message: "Task created", task });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get("/", auth, async (req, res) => {
  try {
    const tasks = await Task.find().populate("course", "title");
    res.json(tasks);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/* ======================
   TASK SUBMISSIONS (STUDENTS)
====================== */
router.post("/submissions", auth, async (req, res) => {
  try {
    const { taskId, content } = req.body;

    const submission = new TaskSubmission({
      task: taskId,
      student: req.user.userId,
      content
    });
    await submission.save();
    res.json({ message: "Submission created", submission });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/* ======================
   VIEW SUBMISSIONS (ADMINS/ASSISTANTS)
====================== */
router.get("/submissions", auth, async (req, res) => {
  try {
    const submissions = await TaskSubmission.find()
      .populate("task", "title")
      .populate("student", "name email")
      .populate("reviewedBy", "name email");

    res.json(submissions);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/* ======================
   REVIEW SUBMISSION (ADMINS/ASSISTANTS)
====================== */
router.patch("/submissions/:id/review", auth, async (req, res) => {
  try {
    const { status } = req.body;

    const submission = await TaskSubmission.findByIdAndUpdate(
      req.params.id,
      { status, reviewedBy: req.user.userId },
      { new: true }
    );

    res.json({ message: "Submission updated", submission });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
