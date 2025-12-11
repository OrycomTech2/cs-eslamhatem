const express = require("express");
const router = express.Router();
const multer = require("multer");
const path = require("path");
const Lesson = require("../models/Lesson");

// Controller
const lessonController = require("../controllers/lessonController");

// Middleware
const authenticateAdmin = require("../middleware/authenticateAdmin");

// ================= Multer setup =================
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "uploads/lessons/");
  },
  filename: function (req, file, cb) {
    const ext = path.extname(file.originalname);
    cb(null, `${Date.now()}-${Math.round(Math.random() * 1e9)}${ext}`);
  }
});

const upload = multer({ storage });

// ================= Routes =================

// Create Lesson (Admin only)
router.post(
  "/",
  authenticateAdmin,
  upload.fields([
    { name: "material", maxCount: 1 },
    { name: "video", maxCount: 1 },
    { name: "thumbnail", maxCount: 1 }
  ]),
  lessonController.createLesson
);

// Update Lesson (Admin only)
router.put(
  "/:id",
  authenticateAdmin,
  upload.fields([
    { name: "material", maxCount: 1 },
    { name: "video", maxCount: 1 },
    { name: "thumbnail", maxCount: 1 }
  ]),
  lessonController.updateLesson
);

// Delete Lesson (Admin only)
router.delete("/:id", authenticateAdmin, lessonController.deleteLesson);



router.post("/save-video", async (req, res) => {
  const { lessonId, videoUrl } = req.body;

  await Lesson.findByIdAndUpdate(lessonId, {
    video: videoUrl
  });

  res.json({ success: true });
});



// List All Lessons
router.get("/", lessonController.listLessons);

// Get Single Lesson
router.get("/:id", lessonController.getLesson);

module.exports = router;
