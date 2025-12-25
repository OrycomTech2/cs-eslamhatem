const express = require("express");
const router = express.Router();
const upload = require("../middleware/upload");
const authenticateAssistant = require("../middleware/authenticateAssistant");

const {
  login,
  getProfile,
  updateProfile,
  changePassword,
  getCourses,
  getAvailableLiveSessions 

} = require("../controllers/assistantController");
const {
  createAssignment,
  listAssignments,
  updateAssignment,
  deleteAssignment,
  listSubmissions,
  scheduleLiveSession,
  listSessions,
  updateLiveSession,
  cancelLiveSession,
  createQuiz,
  listQuizzes,
  updateQuiz,
  deleteQuiz,
  listQuizSubmissions,
  reviewSubmission,
  listStudents,
  getStudentById,
  updateStudent,
  deleteStudent,
  assignCourseToStudent,
  removeCourseFromStudent,
  toggleCompilerAccess,
  uploadPDF,
  getQuizPDF,
  gradeAssignment,
  getQuizSubmissionById,
  gradeQuizAttempt,
  generateSubscriptionCode,
  deleteQuizSubmission,
  getCourseStudents,
  getStudentCourseAssignments,
  getStudentCourseQuizzes,
  deleteAssignmentSubmission,
  getSubmissionById,
  reviewSubmissionquiz
} = require("../controllers/adminController");


/* 🔑 Auth */
router.post("/login", login);
router.get("/profile", authenticateAssistant, getProfile);
router.put("/profile", authenticateAssistant, upload.single("photo"), updateProfile);
router.put("/change-password", authenticateAssistant, changePassword);

/* courses */
router.get("/courses", authenticateAssistant, getCourses);

/* 📝 Assignments */
router.post("/assignments", authenticateAssistant, upload.single("pdf"), createAssignment);
router.get("/assignments", authenticateAssistant, listAssignments);
router.put("/assignments/:id", authenticateAssistant, upload.single("pdf"), updateAssignment);
router.delete("/assignments/:id", authenticateAssistant, deleteAssignment);
router.get("/assignments/submissions", authenticateAssistant, listSubmissions);
router.put("/assignments/submissions/:id/review", authenticateAssistant, reviewSubmission);
router.put("/assignments/submissions/:id/grade", authenticateAssistant, gradeAssignment);

// Add PDF upload middleware to create and update routes
router.post("/quizzes", authenticateAssistant, uploadPDF, createQuiz);
router.get("/quizzes", authenticateAssistant, listQuizzes);
router.delete("/quizzes/:id", authenticateAssistant, deleteQuiz);
router.put("/quizzes/:id", authenticateAssistant, uploadPDF, updateQuiz);
router.get("/quiz-submissions", authenticateAssistant, listQuizSubmissions);
router.get("/quiz-submissions/:id", authenticateAssistant, getQuizSubmissionById);
router.put("/quiz-submissions/:id/review", authenticateAssistant, reviewSubmission);
router.put("/quizzes/attempts/:id/grade", authenticateAssistant, gradeQuizAttempt);
router.get("/quizzes/:id/pdf", authenticateAssistant, getQuizPDF); // New route to get PDF

/* 🎥 Live Sessions */
router.post("/livesessions", authenticateAssistant, scheduleLiveSession);
router.get("/livesessions", authenticateAssistant, listSessions);
router.put("/livesessions/:id", authenticateAssistant, updateLiveSession);
router.delete("/livesessions/:id", authenticateAssistant, cancelLiveSession);
router.get("/available-live-sessions", authenticateAssistant, getAvailableLiveSessions);
router.get("/students", authenticateAssistant, listStudents);
router.get("/students/:id", authenticateAssistant, getStudentById);
router.put("/students/:id", authenticateAssistant, updateStudent);
router.delete("/students/:id", authenticateAssistant, deleteStudent);



// Add these to your admin routes (routes/admin.js)
router.get("/courses/:courseId/students", authenticateAssistant, getCourseStudents);
router.get("/courses/:courseId/students/:studentId/assignments", authenticateAssistant, getStudentCourseAssignments);
router.get("/courses/:courseId/students/:studentId/quizzes", authenticateAssistant, getStudentCourseQuizzes);
router.delete("/submissions/:id", authenticateAssistant, deleteAssignmentSubmission);
router.delete("/quiz-submissions/:id", authenticateAssistant, deleteQuizSubmission);
// Assignment submission routes
router.get("/submissions", authenticateAssistant, listSubmissions); // GET all submissions
router.get("/submissions/:id", authenticateAssistant, getSubmissionById); // GET single submission (you might need to add this)
router.put("/submissions/:id/review", authenticateAssistant, reviewSubmission); // Review submission
router.delete("/submissions/:id", authenticateAssistant, deleteAssignmentSubmission); // Delete submis
module.exports = router;
