const express = require("express");
const router = express.Router();
const path = require("path");
const multer = require("multer");

const AssignmentSubmission = require("../models/Submission");
const SubscriptionCode = require("../models/SubscriptionCode");
const authenticateAdmin = require("../middleware/authenticateAdmin");

const {
  createLesson,
  listLessons,
  updateLesson,
  deleteLesson,
  adminLogin,
  getProfile,
  updateProfile,
  changePassword,
  createCourse,
  updateCourse,
  deleteCourse,
  listCourses,
  createAssignment,
  updateAssignment,
  deleteAssignment,
  listAssignments,
  listSubmissions,
  scheduleLiveSession,
  updateLiveSession,
  cancelLiveSession,
  listSessions,
  listStudents,
  getAllUsers,
  deleteUser,
  createAssistant,
  updateAssistant,
  deleteAssistant,
  listAssistants,
  getAssistantProfile,
  getLessonById,
  uploadLessonFiles,
  createQuiz,
  listQuizzes,
  deleteQuiz,
  updateQuiz,
  listQuizSubmissions,
  reviewSubmission,
  getStudentById,
  updateStudent,
  deleteStudent,
  assignCourseToStudent,
  removeCourseFromStudent,
  toggleCompilerAccess,
  uploadPDF,
  getQuizPDF,
  gradeAssignment,
  gradeQuizAttempt,
  getQuizSubmissionById,
  getAvailableLiveSessions,
  generateSubscriptionCode,
  deleteQuizSubmission,
  getCourseStudents,
  getStudentCourseAssignments,
  getStudentCourseQuizzes,
  deleteAssignmentSubmission,
  getSubmissionById,
  reviewSubmissionquiz
} = require("../controllers/adminController");

const { deleteFromR2 } = require("../services/r2Service");

/* ========================
   📂 Multer Storage Config
======================== */

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    let folder = "uploads/";

    if (file.fieldname === "material") {
      folder = "uploads/materials/";
    } else if (file.fieldname === "thumbnail") {
      folder = "uploads/thumbnails/";
    } else if (file.fieldname === "video") {
      folder = "uploads/videos/";
    } else if (file.fieldname === "pdfFile") {
      folder = "uploads/quizzes/";
    } else if (file.fieldname === "pdf") {
      folder = "uploads/assignments/";
    } else if (file.fieldname === "reviewPdf") {
      folder = "uploads/reviews/";
    } else if (file.fieldname === "photo") {
      folder = "uploads/admins/";
    }

    const fs = require("fs");

    if (!fs.existsSync(folder)) {
      fs.mkdirSync(folder, { recursive: true });
    }

    cb(null, folder);
  },

  filename: (req, file, cb) => {
    const originalName = file.originalname || "file";

    const cleanName = originalName
      .replace(/\s+/g, "_")
      .replace(/[^\w.-]/g, "")
      .replace(/_{2,}/g, "_")
      .toLowerCase();

    const timestamp = Date.now();
    cb(null, `${timestamp}_${cleanName}`);
  }
});

const fileFilter = (req, file, cb) => {
  if (
    file.mimetype.startsWith("video/") ||
    file.mimetype.startsWith("image/") ||
    file.mimetype === "application/pdf" ||
    file.mimetype === "application/msword" ||
    file.mimetype ===
      "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
  ) {
    cb(null, true);
  } else {
    cb(new Error("File type not allowed"), false);
  }
};

const upload = multer({
  storage,
  limits: {
    fileSize: 10 * 1024 * 1024 * 1024
  },
  fileFilter
});

/* ========================
   👩‍🎓 Students
======================== */

router.get("/students", authenticateAdmin, listStudents);
router.get("/students/:id", authenticateAdmin, getStudentById);
router.put("/students/:id", authenticateAdmin, updateStudent);
router.delete("/students/:id", authenticateAdmin, deleteStudent);

router.post("/students/:id/courses", authenticateAdmin, assignCourseToStudent);
router.delete("/students/:id/courses", authenticateAdmin, removeCourseFromStudent);

router.put("/students/:id/compiler", authenticateAdmin, toggleCompilerAccess);

/* ========================
   🔑 Auth
======================== */

router.post("/login", adminLogin);
router.get("/profile", authenticateAdmin, getProfile);
router.put("/profile", authenticateAdmin, upload.single("photo"), updateProfile);
router.put("/change-password", authenticateAdmin, changePassword);

/* ========================
   📚 Courses
======================== */

router.post("/courses", authenticateAdmin, upload.single("thumbnail"), createCourse);
router.get("/courses", authenticateAdmin, listCourses);
router.put("/courses/:id", authenticateAdmin, upload.single("thumbnail"), updateCourse);
router.delete("/courses/:id", authenticateAdmin, deleteCourse);

/* ========================
   📝 Assignments
======================== */

router.use("/assignments", (req, res, next) => {
  console.log("🚦 Assignment route reached:", req.method, req.originalUrl);
  next();
});

router.post("/assignments", authenticateAdmin, upload.single("pdf"), createAssignment);
router.get("/assignments", authenticateAdmin, listAssignments);
router.put("/assignments/:id", authenticateAdmin, upload.single("pdf"), updateAssignment);
router.delete("/assignments/:id", authenticateAdmin, deleteAssignment);

router.get("/assignments/submissions", authenticateAdmin, listSubmissions);

router.delete("/assignments/submissions/:id", authenticateAdmin, async (req, res) => {
  try {
    const submissionId = req.params.id;

    const submission = await AssignmentSubmission.findById(submissionId);

    if (!submission) {
      return res.status(404).json({
        success: false,
        message: "Submission not found"
      });
    }

    if (submission.fileUrl) {
      try {
        await deleteFromR2(submission.fileUrl);
      } catch (fileError) {
        console.error("Error deleting file from R2:", fileError);
      }
    }

    await AssignmentSubmission.findByIdAndDelete(submissionId);

    return res.status(200).json({
      success: true,
      message: "Submission deleted successfully"
    });
  } catch (error) {
    console.error("Error deleting assignment submission:", error);

    return res.status(500).json({
      success: false,
      message: "Server error while deleting submission",
      error: error.message
    });
  }
});

/* ✅ Review assignment submission with optional correction PDF */
router.put(
  "/assignments/submissions/:id/review",
  authenticateAdmin,
  upload.single("reviewPdf"),
  reviewSubmission
);

/* ✅ Grade assignment submission with optional correction PDF */
router.put(
  "/assignments/submissions/:id/grade",
  authenticateAdmin,
  upload.single("reviewPdf"),
  gradeAssignment
);

/* ========================
   🎥 Live Sessions
======================== */

router.post("/livesessions", authenticateAdmin, scheduleLiveSession);
router.get("/livesessions", authenticateAdmin, listSessions);
router.put("/livesessions/:id", authenticateAdmin, updateLiveSession);
router.delete("/livesessions/:id", authenticateAdmin, cancelLiveSession);
router.get("/available-live-sessions", authenticateAdmin, getAvailableLiveSessions);

/* ========================
   👥 Users & Assistants
======================== */

router.get("/users", authenticateAdmin, getAllUsers);
router.delete("/users/:id", authenticateAdmin, deleteUser);

router.post("/assistants", authenticateAdmin, createAssistant);
router.get("/assistants", authenticateAdmin, listAssistants);
router.put("/assistants/:id", authenticateAdmin, updateAssistant);
router.delete("/assistants/:id", authenticateAdmin, deleteAssistant);
router.get("/assistants/:id", authenticateAdmin, getAssistantProfile);

/* ========================
   📚 Lessons
======================== */

router.post(
  "/lessons",
  authenticateAdmin,
  upload.fields([
    { name: "material", maxCount: 1 },
    { name: "video", maxCount: 1 },
    { name: "thumbnail", maxCount: 1 }
  ]),
  createLesson
);

router.get("/lessons", authenticateAdmin, listLessons);

router.put(
  "/lessons/:id",
  authenticateAdmin,
  upload.fields([
    { name: "material", maxCount: 1 },
    { name: "video", maxCount: 1 },
    { name: "thumbnail", maxCount: 1 }
  ]),
  updateLesson
);

router.delete("/lessons/:id", authenticateAdmin, deleteLesson);
router.get("/lessons/:id", authenticateAdmin, getLessonById);

router.put(
  "/lessons/:id/files",
  authenticateAdmin,
  upload.fields([
    { name: "material", maxCount: 1 },
    { name: "thumbnail", maxCount: 1 }
  ]),
  uploadLessonFiles
);

/* ========================
   ❓ Quizzes
======================== */

router.post("/quizzes", authenticateAdmin, upload.single("pdfFile"), createQuiz);
router.get("/quizzes", authenticateAdmin, listQuizzes);
router.delete("/quizzes/:id", authenticateAdmin, deleteQuiz);
router.put("/quizzes/:id", authenticateAdmin, upload.single("pdfFile"), updateQuiz);

router.get("/quiz-submissions", authenticateAdmin, listQuizSubmissions);
router.get("/quiz-submissions/:id", authenticateAdmin, getQuizSubmissionById);
router.delete("/delete/quiz-submissions/:id", authenticateAdmin, deleteQuizSubmission);
router.put("/quiz-submissions/:id/review", authenticateAdmin, reviewSubmissionquiz);
router.put("/quizzes/attempts/:id/grade", authenticateAdmin, gradeQuizAttempt);
router.get("/quizzes/:id/pdf", authenticateAdmin, getQuizPDF);

/* ========================
   🔑 Subscription Codes
======================== */

router.post("/subscription-codes", authenticateAdmin, generateSubscriptionCode);

/* ========================
   📌 Course Student Details
======================== */

router.get("/courses/:courseId/students", authenticateAdmin, getCourseStudents);

router.get(
  "/courses/:courseId/students/:studentId/assignments",
  authenticateAdmin,
  getStudentCourseAssignments
);

router.get(
  "/courses/:courseId/students/:studentId/quizzes",
  authenticateAdmin,
  getStudentCourseQuizzes
);

/* ========================
   📤 General Assignment Submission Routes
======================== */

router.get("/submissions", authenticateAdmin, listSubmissions);
router.get("/submissions/:id", authenticateAdmin, getSubmissionById);

router.put(
  "/submissions/:id/review",
  authenticateAdmin,
  upload.single("reviewPdf"),
  reviewSubmission
);

router.delete("/submissions/:id", authenticateAdmin, deleteAssignmentSubmission);
router.delete("/quiz-submissions/:id", authenticateAdmin, deleteQuizSubmission);

module.exports = router;
