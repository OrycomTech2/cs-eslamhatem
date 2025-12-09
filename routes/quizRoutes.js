const express = require("express");
const router = express.Router();
const multer = require("multer");
const quizController = require("../controllers/quizController");
const path = require("path");
const storage = multer.diskStorage({
  destination: "uploads/quizzes/",
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname));
  }
});

const upload = multer({ storage });

router.post("/", upload.single("pdfFile"), quizController.createQuiz);

// CRUD
router.get("/", quizController.listQuizzes);
router.get("/:id", quizController.getQuiz);
router.put("/:id", quizController.updateQuiz);
router.delete("/:id", quizController.deleteQuiz);

// Attempts
router.post("/:id/submit", quizController.submitQuiz);
router.get("/:id/submissions", quizController.listSubmissions);

module.exports = router;
