// controllers/contentController.js
const Content = require('../models/Content');
const mongoose = require('mongoose');
const User = require('../models/User');
const auth = require('../middleware/auth');
const AssignmentSubmission = require("../models/AssignmentSubmission");

exports.uploadInstructorContent = async (req, res) => {
  try {
    console.log("📥 Upload Instructor Content called");

    const { title, courseId, description, duration, assignments, quizzes } = req.body;

    const newLesson = new Content({
      title,
      course: courseId,
      description,
      duration,
      assignments: assignments ? JSON.parse(assignments) : [],
      quizzes: quizzes ? JSON.parse(quizzes) : []
    });

    if (req.file) {
      // save depending on type
      newLesson.video = req.file.mimetype.includes("video") ? req.file.path : undefined;
      newLesson.pdf = req.file.mimetype.includes("pdf") ? req.file.path : undefined;
      newLesson.thumbnail = req.file.mimetype.includes("image") ? req.file.path : undefined;
    }

    await newLesson.save();
    res.status(201).json({ message: 'Lesson uploaded successfully', data: newLesson });
  } catch (err) {
    console.error("❌ Error uploading lesson:", err);
    res.status(500).json({ message: 'Server error' });
  }
};



exports.getInstructorContent = async (req, res) => {
  try {
    const contents = await Content.find({ instructor: req.params.id }).populate('course');
    res.json(contents);
  } catch (err) {
    res.status(500).json({ message: 'Failed to fetch instructor content' });
  }
};


// GET single content
exports.getInstructorContentById = async (req, res) => {
  try {
    const content = await Content.findById(req.params.id);
    if (!content) return res.status(404).json({ message: 'Not found' });
    res.json(content);
  } catch (err) {
    res.status(500).json({ message: 'Failed to fetch content' });
  }
};

// PUT update content
exports.updateInstructorContent = async (req, res) => {
  try {
    const { title, type, course } = req.body;
    const updateData = { title, type, course };

    if (req.file) {
      updateData.file = req.file.filename;
    }

    const updated = await Content.findByIdAndUpdate(req.params.id, updateData, { new: true });
    if (!updated) return res.status(404).json({ message: 'Not found' });

    res.json({ message: 'Content updated', updated });
  } catch (err) {
    console.error('Update error:', err);
    res.status(500).json({ message: 'Update failed' });
  }
};

exports.getMyAssignments = async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).populate('paidCourses');
    if (!user) return res.status(404).json({ error: "User not found" });

    const courseIds = user.paidCourses.map(c => c._id);

    const lessons = await Content.find({
      course: { $in: courseIds },
      assignments: { $exists: true, $ne: [] }
    })
      .select("title assignments course")
      .populate("course", "title"); // get course title too

    const assignments = lessons.flatMap(lesson =>
      (lesson.assignments || []).map(a => ({
        _id: a._id,
        lessonId: lesson._id,
        lessonTitle: lesson.title || "Untitled Lesson",
        courseId: lesson.course?._id,
        courseTitle: lesson.course?.title || "Untitled Course",
        question: a.question || "No question",
        dueDate: a.dueDate || null
      }))
    );

    res.json(assignments);
  } catch (err) {
    console.error("❌ getMyAssignments error:", err);
    res.status(500).json({ error: err.message });
  }
};


exports.submitAssignment = async (req, res) => {
  try {
    const { id } = req.params;
    const { lessonId, courseId } = req.body;

    const submission = await AssignmentSubmission.create({
      id,
      lessonId,
      courseId,
      studentId: req.user.id,
      fileUrl: req.file.filename
    });

    res.json({ message: "Assignment submitted successfully", submission });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

exports.getMySubmissions = async (req, res) => {
  try {
    const submissions = await AssignmentSubmission.find({ studentId: req.user.id })
      .populate("courseId")
      .populate("lessonId")
      .populate("id");
    res.json(submissions);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};
