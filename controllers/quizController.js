const Quiz = require("../models/Quiz");
const Question = require("../models/Question");
const QuizAttempt = require("../models/QuizAttempt");

/* ========================
   🔹 Create Quiz
======================== */
exports.createQuiz = async (req, res) => {
  try {
    const { title, description, type, duration, course } = req.body;
    let quizData = { title, description, type, duration, course };

    if (type === "pdf") {
      if (!req.file) return res.status(400).json({ error: "PDF file required" });
      quizData.pdfUrl = req.file.path;
    } else if (type === "structured") {
      const questions = JSON.parse(req.body.questions || "[]");
      const newQuestions = await Question.insertMany(questions.map(q => ({ ...q })));
      quizData.questions = newQuestions.map(q => q._id);
      quizData.totalMarks = newQuestions.reduce((s, q) => s + q.marks, 0);
    }

    const quiz = await Quiz.create(quizData);
    res.json({ success: true, data: quiz });
  } catch (err) {
    console.error("Create quiz error:", err);
    res.status(500).json({ error: "Server error" });
  }
};


/* ========================
   🔹 List Quizzes
======================== */
exports.listQuizzes = async (req, res) => {
  try {
    const quizzes = await Quiz.find()
      .populate("course", "title")
      .populate("questions");
    res.json({ success: true, data: quizzes });
  } catch (err) {
    console.error("List quizzes error:", err);
    res.status(500).json({ error: "Server error" });
  }
};

/* ========================
   🔹 Get Single Quiz
======================== */
exports.getQuiz = async (req, res) => {
  try {
    const quiz = await Quiz.findById(req.params.id).populate("questions");
    if (!quiz) return res.status(404).json({ error: "Quiz not found" });
    res.json({ success: true, data: quiz });
  } catch (err) {
    console.error("Get quiz error:", err);
    res.status(500).json({ error: "Server error" });
  }
};

/* ========================
   🔹 Update Quiz
======================== */
exports.updateQuiz = async (req, res) => {
  try {
    const { title, description, duration, type, questions } = req.body;
    const quiz = await Quiz.findById(req.params.id);
    if (!quiz) return res.status(404).json({ error: "Quiz not found" });

    quiz.title = title || quiz.title;
    quiz.description = description || quiz.description;
    quiz.duration = duration || quiz.duration;
    quiz.type = type || quiz.type;

    if (type === "structured" && questions) {
      await Question.deleteMany({ quiz: quiz._id });
      const newQuestions = await Question.insertMany(
        questions.map(q => ({
          quiz: quiz._id,
          text: q.text,
          type: q.type || "mcq",
          options: q.options || [],
          correctAnswer: q.correctAnswer,
          marks: q.marks || 1,
        }))
      );
      quiz.questions = newQuestions.map(q => q._id);
      quiz.totalMarks = newQuestions.reduce((sum, q) => sum + q.marks, 0);
    }

    await quiz.save();
    res.json({ success: true, data: quiz });
  } catch (err) {
    console.error("Update quiz error:", err);
    res.status(500).json({ error: "Server error" });
  }
};

/* ========================
   🔹 Delete Quiz
======================== */
exports.deleteQuiz = async (req, res) => {
  try {
    await Question.deleteMany({ quiz: req.params.id });
    await Quiz.findByIdAndDelete(req.params.id);
    res.json({ success: true, message: "Quiz deleted" });
  } catch (err) {
    console.error("Delete quiz error:", err);
    res.status(500).json({ error: "Server error" });
  }
};

/* ========================
   🔹 Submit Quiz Attempt
======================== */
exports.submitQuiz = async (req, res) => {
  try {
    const { quizId, studentId, answers } = req.body;
    const quiz = await Quiz.findById(quizId).populate("questions");
    if (!quiz) return res.status(404).json({ error: "Quiz not found" });

    let totalScore = 0;
    const evaluatedAnswers = answers.map(ans => {
      const q = quiz.questions.find(q => q._id.toString() === ans.questionId);
      let isCorrect = false, marksObtained = 0;

      if (q && q.correctAnswer && q.correctAnswer.toLowerCase() === ans.response.toLowerCase()) {
        isCorrect = true;
        marksObtained = q.marks;
      }
      totalScore += marksObtained;

      return { question: ans.questionId, response: ans.response, isCorrect, marksObtained };
    });

    const attempt = await QuizAttempt.create({
      quiz: quizId,
      student: studentId,
      answers: evaluatedAnswers,
      score: totalScore,
    });

    res.status(201).json({ success: true, data: attempt });
  } catch (err) {
    console.error("Submit quiz error:", err);
    res.status(500).json({ error: "Server error" });
  }
};

/* ========================
   🔹 List Submissions
======================== */
exports.listSubmissions = async (req, res) => {
  try {
    const attempts = await QuizAttempt.find({ quiz: req.params.id })
      .populate("student", "name email")
      .populate("quiz", "title")
      .populate("answers.question", "text correctAnswer marks");
    res.json({ success: true, data: attempts });
  } catch (err) {
    console.error("List submissions error:", err);
    res.status(500).json({ error: "Server error" });
  }
};
