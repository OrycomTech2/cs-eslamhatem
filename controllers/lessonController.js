const Lesson = require("../models/Lesson");
const Course = require("../models/Course");
const path = require("path");
const fs = require("fs");

// ========================
// Create a lesson (Admin only)
// POST /api/lessons
// ========================
exports.createLesson = async (req, res) => {
  try {
    const { title, description, courseId, type, price } = req.body;

    if (!title || !courseId || !type) {
      return res.status(400).json({ message: "Missing required fields" });
    }

    // Check if course exists
    const course = await Course.findById(courseId);
    if (!course) return res.status(404).json({ message: "Course not found" });

    // Handle uploaded files
    const material = req.files?.material ? `/uploads/${req.files.material[0].filename}` : null;
    const video = req.files?.video ? `/uploads/${req.files.video[0].filename}` : null;
    const thumbnail = req.files?.thumbnail ? `/uploads/${req.files.thumbnail[0].filename}` : null;

    const lesson = new Lesson({
      title,
      description,
      type,
      price,
      course: courseId,
      material,
      video,
      thumbnail
    });

    await lesson.save();

    // Add lesson to course
    course.lessons.push(lesson._id);
    await course.save();

    res.status(201).json({ success: true, lesson });
  } catch (err) {
    console.error("Create lesson error:", err);
    res.status(500).json({ message: "Server error" });
  }
};

// ========================
// Update lesson (Admin only)
// PUT /api/lessons/:id
// ========================
exports.updateLesson = async (req, res) => {
  try {
    const lessonId = req.params.id;
    const { title, description, type, price } = req.body;

    const lesson = await Lesson.findById(lessonId);
    if (!lesson) return res.status(404).json({ message: "Lesson not found" });

    // Update files if uploaded
    if (req.files?.material) lesson.material = `/uploads/${req.files.material[0].filename}`;
    if (req.files?.video) lesson.video = `/uploads/${req.files.video[0].filename}`;
    if (req.files?.thumbnail) lesson.thumbnail = `/uploads/${req.files.thumbnail[0].filename}`;

    // Update other fields
    if (title) lesson.title = title;
    if (description) lesson.description = description;
    if (type) lesson.type = type;
    if (price) lesson.price = price;

    await lesson.save();

    res.json({ success: true, lesson });
  } catch (err) {
    console.error("Update lesson error:", err);
    res.status(500).json({ message: "Server error" });
  }
};

// ========================
// Delete lesson (Admin only)
// DELETE /api/lessons/:id
// ========================
exports.deleteLesson = async (req, res) => {
  try {
    const lessonId = req.params.id;

    const lesson = await Lesson.findByIdAndDelete(lessonId);
    if (!lesson) return res.status(404).json({ message: "Lesson not found" });

    // Remove lesson from course
    await Course.findByIdAndUpdate(lesson.course, { $pull: { lessons: lesson._id } });

    // Optionally delete uploaded files
    ["material", "video", "thumbnail"].forEach(fileField => {
      if (lesson[fileField]) {
        const filePath = path.join(__dirname, "..", lesson[fileField]);
        if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
      }
    });

    res.json({ success: true, message: "Lesson deleted" });
  } catch (err) {
    console.error("Delete lesson error:", err);
    res.status(500).json({ message: "Server error" });
  }
};

/* ========================
   📚 List Lessons
======================== */
exports.listLessons = async (req, res) => {
  try {
    const lessons = await Lesson.find().populate("assignments quizzes course");
    res.json({ success: true, lessons });
  } catch (err) {
    console.error("List lessons error:", err);
    res.status(500).json({ error: "Server error" });
  }
};

/* ========================
   📚 Get Single Lesson
======================== */
exports.getLesson = async (req, res) => {
  try {
    const lesson = await Lesson.findById(req.params.id).populate("assignments quizzes course");
    if (!lesson) return res.status(404).json({ error: "Lesson not found" });
    res.json({ success: true, lesson });
  } catch (err) {
    console.error("Get lesson error:", err);
    res.status(500).json({ error: "Server error" });
  }
};

