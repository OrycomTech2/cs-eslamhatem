const express = require("express");
const router = express.Router();
const upload = require("../middleware/upload");
const authenticateUser = require("../middleware/authenticate");

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
  getCompilerAccess
} = require("../controllers/studentController");

/* 👤 Profile */
router.get("/profile", authenticateUser, getProfile);
router.put("/profile", authenticateUser, upload.single("photo"), updateProfile);
router.put("/change-password", authenticateUser, changePassword);

/* 📚 Courses */
// static route first
router.get("/courses/available", authenticateUser, getAvailableCourses);

// dynamic route after
router.get("/courses/:id", authenticateUser, getCourseById);
router.get("/courses/my", authenticateUser, getMyCourses);

/* 📝 Assignments */
router.get("/assignments/my", authenticateUser, getMyAssignments);
router.post("/assignments/submit", authenticateUser, submitAssignment);

/* ❓ Quizzes */
router.get("/quizzes/my", authenticateUser, getMyQuizzes);
router.post("/quizzes/submit", authenticateUser, submitQuiz);

/* 🎥 Live Sessions */
router.get("/sessions", authenticateUser, getLiveSessions);

/* 💻 Compiler */
router.get("/compiler", authenticateUser, getCompilerAccess);

module.exports = router;
