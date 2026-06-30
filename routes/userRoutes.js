const express = require("express");
const router = express.Router();
const path = require("path");
const fs = require("fs");
const multer = require("multer");
const authenticate = require("../middleware/authenticate");
const SubscriptionCode = require("../models/SubscriptionCode");
const userController = require("../controllers/userController");
const {
  getProfile,
  updateProfile,
  changePassword,
  getAvailableCourses,
  getMyCourses,
  getMyAssignments,
  submitAssignment,
  getMyQuizzes,
  submitQuiz,
  getLiveSessions,
  getCompilerAccess,
  getCourseById,
  getAvailableLessons,
  submitPdfQuiz,
  getQuiz,
  uploadQuizAnswer,
  getUserQuizAttempt,
  startQuiz
} = require("../controllers/studentController");

const { getUserLiveSessions } = require("../controllers/liveSessionController");
// ================= Multer setup =================
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "uploads/profile/");
  },
  filename: function (req, file, cb) {
    const ext = path.extname(file.originalname);
    cb(null, `${Date.now()}-${Math.round(Math.random() * 1e9)}${ext}`);
  }
});
const upload = multer({ storage });



/* 📚 Courses */
// static route first
router.get("/courses/available", authenticate, getAvailableCourses);

/* Lessons */
// static route first
router.get("/lessons/available", authenticate, getAvailableLessons);

router.get("/lessons/:id", authenticate, userController.getLessonById);
router.get("/courses/:courseId/lessons", authenticate, userController.getLessonsByCourse);
router.get("/:id/video", authenticate, userController.streamLessonVideo);

// dynamic route after
router.get("/courses/:id", authenticate, getCourseById);
router.get("/courses/my", authenticate, getMyCourses);

/* 📝 Assignments */


router.get("/my-assignments", authenticate, getMyAssignments);

router.post("/submit-assignment", authenticate, upload.single("file"), submitAssignment);

/* ❓ Quizzes */
router.get("/quizzes/my", authenticate, getMyQuizzes);

// Start must be before opening/submitting
router.post("/quizzes/:quizId/start", authenticate, startQuiz);

// Attempt check route
router.get("/quizzes/:quizId/attempt", authenticate, getUserQuizAttempt);

// Keep old frontend compatibility if some pages use /:quizId/attempt
router.get("/:quizId/attempt", authenticate, getUserQuizAttempt);

router.get("/quizzes/:id", authenticate, getQuiz);

router.post("/quizzes/:quizId/submit", authenticate, submitQuiz);

router.post("/quizzes/submit-pdf", authenticate, upload.single("answerFile"), submitPdfQuiz);

router.post(
  "/quizzes/:quizId/upload",
  authenticate,
  upload.single("answer"),
  uploadQuizAnswer
);


/* ❓ Quizzes */
router.get("/quizzes/my", authenticate, getMyQuizzes);

// Start must be before opening/submitting
router.post("/quizzes/:quizId/start", authenticate, startQuiz);

// Attempt check route
router.get("/quizzes/:quizId/attempt", authenticate, getUserQuizAttempt);

// Keep old frontend compatibility if some pages use /:quizId/attempt
router.get("/:quizId/attempt", authenticate, getUserQuizAttempt);

router.get("/quizzes/:id", authenticate, getQuiz);

router.post("/quizzes/:quizId/submit", authenticate, submitQuiz);

router.post("/quizzes/submit-pdf", authenticate, upload.single("answerFile"), submitPdfQuiz);

router.post(
  "/quizzes/:quizId/upload",
  authenticate,
  upload.single("answer"),
  uploadQuizAnswer
);


/* 💻 Compiler */
router.get("/compiler", authenticate, getCompilerAccess);


/* ========================
   👤 Profile Management
======================== */
router.get("/profile", authenticate, userController.getProfile);
router.put("/update-photo", authenticate, upload.single("photo"), userController.updateProfilePhoto);
router.put("/update-info", authenticate, userController.updateUserInfo);
router.put("/change-password", authenticate, userController.changeUserPassword);

/* ========================
   📚 Courses
======================== */
router.get("/my-courses", authenticate, userController.getMyCourses);
router.get("/my-lessons", authenticate, userController.getMyLessons); 
router.get("/:courseId/lessons", authenticate, userController.getCourseLessons);




router.post("/enroll/:courseId", authenticate, userController.enrollUserInCourse);
router.post("/:userId/buy-course/:courseId", authenticate, userController.buyCourse); // ✅ moved logic to controller

/* ========================
   🖼 Profile Photo by ID
======================== */
router.get("/:id/photo", async (req, res) => {
  try {
    const user = await userController.findUserById(req.params.id); // helper in controller
    if (!user || !user.photo) {
      return res.status(404).send("Photo not found");
    }

    const filePath = path.join(__dirname, "..", user.photo);
    if (!fs.existsSync(filePath)) {
      return res.status(404).send("File not found on disk");
    }

    res.sendFile(filePath);
  } catch (err) {
    console.error("Error fetching user photo:", err);
    res.status(500).json({ error: "Server error" });
  }
});

/* ========================
   📊 Dashboard
======================== */
router.get("/dashboard", authenticate, userController.getDashboardData);

/* ========================
   🎥 Live Sessions
======================== */
router.get("/available-live-sessions", authenticate, userController.getAvailableLiveSessions);

/* ========================
   (❌ Removed: Admin endpoints)
======================== */
// router.get("/", userController.getAllUsers); // ⛔ moved to adminRoutes.js


// Get user by ID
router.get('/:id', async (req, res) => {
    try {
        const user = await User.findById(req.params.id).select('name email username');
        if (!user) {
            return res.status(404).json({ status: 'error', message: 'User not found' });
        }
        res.json({ status: 'success', data: user });
    } catch (err) {
        res.status(500).json({ status: 'error', message: err.message });
    }
});

// Get multiple users by IDs (for batch fetching)
router.post('/batch', async (req, res) => {
    try {
        const { userIds } = req.body;
        if (!userIds || !Array.isArray(userIds)) {
            return res.status(400).json({ status: 'error', message: 'User IDs array required' });
        }

        const users = await User.find({ _id: { $in: userIds } }).select('name email username');
        res.json({ status: 'success', data: users });
    } catch (err) {
        res.status(500).json({ status: 'error', message: err.message });
    }
});



router.post("/subscription-codes/redeem", authenticate, userController.redeemSubscriptionCode);

router.post("/redeem-code", authenticate, async (req, res) => {
  try {
    const { code } = req.body;
    const subCode = await SubscriptionCode.findOne({ code }).populate("package");

    if (!subCode) return res.status(400).json({ success: false, message: "Invalid code" });
    if (subCode.used) return res.status(400).json({ success: false, message: "Code already used" });

    // Enroll user in all courses inside the package
    const user = await User.findById(req.user.userId);
    subCode.package.courses.forEach(courseId => {
      if (!user.paidCourses.includes(courseId)) {
        user.paidCourses.push(courseId);
      }
    });

    await user.save();
    subCode.used = true;
    subCode.usedBy = user._id;
    await subCode.save();

    res.json({ success: true, message: "Code redeemed, courses unlocked!", courses: user.paidCourses });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});


module.exports = router;
