const bcrypt = require("bcryptjs");
const User = require("../models/User");
const Course = require("../models/Course");
const Assignment = require("../models/Assignment");
const Submission = require("../models/Submission");
const Quiz = require("../models/Quiz");
const QuizAttempt = require("../models/QuizAttempt");
const LiveSession = require("../models/LiveSession");
const Lesson = require("../models/Lesson");

/* ========================
   👤 Profile
======================== */
exports.getProfile = async (req, res) => {
  try {
    const student = await User.findById(req.user.userId).select("-password");
    if (!student || student.role !== "student") {
      return res.status(403).json({ message: "Forbidden" });
    }
    res.json({ student });
  } catch (err) {
    console.error("Get student profile error:", err);
    res.status(500).json({ message: "Server error" });
  }
};

exports.updateProfile = async (req, res) => {
  try {
    const { name, phoneNumber, parentName, parentPhone } = req.body;
    const photo = req.file ? `/uploads/${req.file.filename}` : undefined;

    const updatedStudent = await User.findByIdAndUpdate(
      req.user.userId,
      { $set: { name, phoneNumber, parentName, parentPhone, ...(photo && { photo }) } },
      { new: true }
    ).select("-password");

    res.json({ student: updatedStudent });
  } catch (err) {
    console.error("Update student profile error:", err);
    res.status(500).json({ message: "Server error" });
  }
};



exports.changePassword = async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    const student = await User.findById(req.user.userId);
    if (!student) return res.status(404).json({ message: "Student not found" });

    const isMatch = await bcrypt.compare(currentPassword, student.password);
    if (!isMatch) return res.status(400).json({ message: "Incorrect current password" });

    student.password = await bcrypt.hash(newPassword, 10);
    await student.save();
    res.json({ message: "Password updated successfully" });
  } catch (err) {
    console.error("Change password error:", err);
    res.status(500).json({ message: "Server error" });
  }
};

/* ========================
   📚 Lessons & Packages
======================== */
// controllers/courseController.js
exports.getAvailableCourses = async (req, res) => {
  try {
    const { search, type, page = 1, limit = 10 } = req.query;
    const query = {};

    if (search) {
      query.$or = [
        { title: { $regex: search, $options: "i" } },
        { description: { $regex: search, $options: "i" } }
      ];
    }

    if (type) query.type = type;

    const skip = (page - 1) * limit;

    let courses = await Course.find(query)
      .select("title description price type thumbnail students")
      .skip(skip)
      .limit(Number(limit));

    // add enrolled flag for current user
    const userId = req.user.id;
    courses = courses.map(course => {
      const enrolled = course.students.some(s => s.toString() === userId);
      return {
        ...course.toObject(),
        isEnrolled: enrolled
      };
    });

    const total = await Course.countDocuments(query);

    res.json({
      success: true,
      data: courses,
      pagination: {
        total,
        page: Number(page),
        pages: Math.ceil(total / limit)
      }
    });
  } catch (err) {
    console.error("Get available courses error:", err);
    res.status(500).json({ error: "Server error" });
  }
};
exports.getAvailableLessons = async (req, res) => {
  try {
    const { search, type, course, page = 1, limit = 10 } = req.query;
    const query = {};

    // 🔍 Search by title or description
    if (search) {
      query.$or = [
        { title: { $regex: search, $options: "i" } },
        { description: { $regex: search, $options: "i" } }
      ];
    }

    // 🎯 Filter by type (Theoretical / Practical)
    if (type) query.type = type;

    // 📚 Filter by course (if provided)
    if (course) query.course = course;

    const skip = (page - 1) * limit;

    let lessons = await Lesson.find(query)
      .select("title description type price thumbnail material video course")
      .populate("course", "title") // optional, to show course title
      .skip(skip)
      .limit(Number(limit));

    const total = await Lesson.countDocuments(query);

    res.json({
      success: true,
      data: lessons,
      pagination: {
        total,
        page: Number(page),
        pages: Math.ceil(total / limit)
      }
    });
  } catch (err) {
    console.error("Get available lessons error:", err);
    res.status(500).json({ error: "Server error" });
  }
};

exports.getCourseById = async (req, res) => {
  try {
    const { id } = req.params;

    const course = await Course.findById(id)
      .populate("instructor", "name email")   // show instructor info
      .populate("assistants", "name email")   // show assistants
      .populate("lessons", "title type")      // only basic info
      .populate("assignments", "title dueDate")
      .populate("liveSessions", "title date link");

    if (!course) {
      return res.status(404).json({ success: false, error: "Course not found" });
    }

    res.json({ success: true, data: course });
  } catch (err) {
    console.error("Get course by ID error:", err);
    res.status(500).json({ success: false, error: "Server error" });
  }
};
exports.getMyCourses = async (req, res) => {
  try {
    const student = await User.findById(req.user.userId).populate("paidCourses");
    res.json({ success: true, data: student.paidCourses });
  } catch (err) {
    console.error("Get my courses error:", err);
    res.status(500).json({ error: "Server error" });
  }
};

/* ========================
   📝 Assignments
======================== */
// controllers/userController.js
exports.getMyAssignments = async (req, res) => {
  try {
    const assignments = await Assignment.find()
      .lean();

    // find submissions by this user
    const submissions = await Submission.find({ student: req.user.userId }).lean();

    // merge submissions with assignments
    const data = assignments.map(assign => {
      const submission = submissions.find(s => String(s.assignment) === String(assign._id));
      return {
        ...assign,
        submission: submission || null
      };
    });

    res.json({ success: true, data });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: "Server error" });
  }
};


exports.submitAssignment = async (req, res) => {
  try {
    const { assignmentId, textAnswer } = req.body;

    const submission = new Submission({
      student: req.user.userId,
      assignment: assignmentId,
      textAnswer: textAnswer || null,
      fileUrl: req.file ? req.file.path : null
    });

    await submission.save();

    // Push submission into assignment
    await Assignment.findByIdAndUpdate(assignmentId, { $push: { submissions: submission._id } });

    res.json({ success: true, data: submission });
  } catch (err) {
    console.error("Submit assignment error:", err);
    res.status(500).json({ error: "Server error" });
  }
};


/* ========================
   ❓ Quizzes
======================== */


exports.getMyQuizzes = async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).populate({
      path: "paidCourses",
      populate: { path: "Quiz", model: "Quiz" }
    });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const attempts = await QuizAttempt.find({ student: req.user.userId })
      .populate("quiz");

    const attemptsMap = {};
    attempts.forEach(a => {
      if (a.quiz) { // Add null check
        attemptsMap[a.quiz._id] = a;
      }
    });

    let quizzes = [];
    user.paidCourses.forEach(course => {
      // Add null/undefined checks
      if (course && course.Quiz && Array.isArray(course.Quiz)) {
        course.Quiz.forEach(q => {
          if (q) { // Check if quiz exists
            const attempt = attemptsMap[q._id] || null;
            quizzes.push({
              quizId: q._id,
              title: q.title,
              description: q.description,
              type: q.examType,
              examType: q.examType,
              duration: q.duration,
              attempted: !!attempt,
              submittedAt: attempt ? attempt.createdAt : null,
              score: attempt ? attempt.score : null,
              feedback: attempt ? attempt.feedback : null,
              reviewedAt: attempt ? attempt.reviewedAt : null,
            });
          }
        });
      }
    });

    res.json({ success: true, data: quizzes });
  } catch (err) {
    console.error("Get my quizzes error:", err);
    res.status(500).json({ error: "Server error" });
  }
};



exports.getQuiz = async (req, res) => {
  try {
    const quiz = await Quiz.findById(req.params.id)
      .populate("questions"); // optional if you want questions data

    if (!quiz) {
      return res.status(404).json({ error: "Quiz not found" });
    }

    res.json(quiz);
  } catch (error) {
    console.error("Get quiz error:", error);
    res.status(500).json({ error: "Failed to fetch quiz" });
  }
};


// controllers/studentController.js (or wherever you keep it)
exports.submitQuiz = async (req, res) => {
  try {
    const { quizId } = req.params;
    const { answers, pendingTime } = req.body;

    if (!quizId) return res.status(400).json({ error: "quizId is missing" });

    // Prevent duplicate submissions
    const existing = await QuizAttempt.findOne({ quiz: quizId, student: req.user.userId });
    if (existing) return res.status(400).json({ error: "You already submitted this quiz" });

    // Fetch quiz
    const quiz = await Quiz.findById(quizId).populate("questions");
    if (!quiz) return res.status(404).json({ error: "Quiz not found" });

    // Map answers with question IDs
    const mappedAnswers = answers.map((a, index) => ({
      question: quiz.questions[index]?._id,
      answer: a.answer || "",
      marksObtained: 0,
      isCorrect: false,
    }));

    const pendingUntil = pendingTime
      ? new Date(Date.now() + pendingTime * 60 * 1000)
      : null;

    // Create attempt
    const attempt = new QuizAttempt({
      student: req.user.userId,
      quiz: quizId,
      answers: mappedAnswers,
      pendingUntil,
    });

    await attempt.save();

    // 🔥 Push attempt into quiz.attempts[]
    quiz.attempts.push(attempt._id);
    await quiz.save();

    res.json({ success: true, data: attempt });
  } catch (err) {
    console.error("Submit quiz error:", err);
    res.status(500).json({ error: "Server error" });
  }
};




exports.uploadQuizAnswer = async (req, res) => {
  try {
    const { quizId } = req.params;
    const studentId = req.user.userId;

    if (!req.file) {
      return res.status(400).json({ error: "No file uploaded" });
    }

    // Create a new attempt with the uploaded file
    const attempt = new QuizAttempt({
      quiz: quizId,
      student: studentId,
      pdfAnswerFile: req.file.path,  // ✅ store file path
      status: "pending"
    });

    await attempt.save();

    res.json({ message: "Answer file uploaded successfully", attempt });
  } catch (err) {
    console.error("Upload quiz answer error:", err);
    res.status(500).json({ error: "Server error" });
  }
};



exports.submitPdfQuiz = async (req, res) => {
  try {
    const { quizId, pendingTime } = req.body;

    if (!req.file) {
      return res.status(400).json({ error: "Answer file is required" });
    }

    const existing = await QuizAttempt.findOne({ quiz: quizId, student: req.user.userId });
    if (existing) {
      return res.status(400).json({ error: "You already submitted this quiz" });
    }

    const pendingUntil = pendingTime
      ? new Date(Date.now() + pendingTime * 60 * 1000)
      : null;

    const attempt = new QuizAttempt({
      student: req.user.userId,
      quiz: quizId,
      pdfAnswerFile: req.file.path,
      pendingUntil
    });

    await attempt.save();
    res.json({ success: true, data: attempt });
  } catch (err) {
    console.error("Submit PDF quiz error:", err);
    res.status(500).json({ error: "Server error" });
  }
};





/* ========================
   🎥 Online Meetings
======================== */
exports.getLiveSessions = async (req, res) => {
  try {
    const sessions = await LiveSession.find({ course: { $in: req.user.paidCourses } });
    res.json({ success: true, data: sessions });
  } catch (err) {
    console.error("Get live sessions error:", err);
    res.status(500).json({ error: "Server error" });
  }
};

/* ========================
   💻 Compiler
======================== */
exports.getCompilerAccess = async (req, res) => {
  try {
    const student = await User.findById(req.user.userId);
    res.json({ compilerAccess: student.hasCompilerAccess });
  } catch (err) {
    console.error("Get compiler access error:", err);
    res.status(500).json({ error: "Server error" });
  }
};

exports.getUserQuizAttempt = async (req, res) => {
  try {
    const { quizId } = req.params;
    const userId = req.user.userId;

    // Find user's attempt
    const attempt = await QuizAttempt.findOne({ quiz: quizId, student: userId });

    if (!attempt) {
      return res.json({ success: true, attempt: null });
    }

    res.json({ success: true, attempt });
  } catch (err) {
    console.error("Get user quiz attempt error:", err);
    res.status(500).json({ error: "Failed to get quiz attempt" });
  }
};
