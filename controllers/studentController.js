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
      {
        $set: {
          name,
          phoneNumber,
          parentName,
          parentPhone,
          ...(photo && { photo })
        }
      },
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

    if (!student) {
      return res.status(404).json({ message: "Student not found" });
    }

    const isMatch = await bcrypt.compare(currentPassword, student.password);

    if (!isMatch) {
      return res.status(400).json({ message: "Incorrect current password" });
    }

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

    const userId = req.user.userId || req.user.id;

    courses = courses.map(course => {
      const enrolled = course.students.some(s => s.toString() === String(userId));

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

    if (search) {
      query.$or = [
        { title: { $regex: search, $options: "i" } },
        { description: { $regex: search, $options: "i" } }
      ];
    }

    if (type) query.type = type;
    if (course) query.course = course;

    const skip = (page - 1) * limit;

    const lessons = await Lesson.find(query)
      .select("title description type price thumbnail material video course")
      .populate("course", "title")
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
      .populate("instructor", "name email")
      .populate("assistants", "name email")
      .populate("lessons", "title type")
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
exports.getMyAssignments = async (req, res) => {
  try {
    const assignments = await Assignment.find().lean();
    const submissions = await Submission.find({ student: req.user.userId })
  .select(
    "assignment fileUrl textAnswer grade feedback reviewPdfUrl reviewPdfOriginalName reviewedAt createdAt isLate lateByText submittedAt"
  )
  .lean();

    const data = assignments.map(assign => {
      const submission = submissions.find(
        s => String(s.assignment) === String(assign._id)
      );

      return {
        ...assign,
        submission: submission || null
      };
    });

    res.json({ success: true, data });
  } catch (err) {
    console.error("Get my assignments error:", err);
    res.status(500).json({ success: false, error: "Server error" });
  }
};


function formatLateDuration(ms) {
  if (!ms || ms <= 0) return null;

  const totalMinutes = Math.floor(ms / (1000 * 60));
  const days = Math.floor(totalMinutes / (60 * 24));
  const hours = Math.floor((totalMinutes % (60 * 24)) / 60);
  const minutes = totalMinutes % 60;

  const parts = [];
  if (days) parts.push(`${days} day${days > 1 ? "s" : ""}`);
  if (hours) parts.push(`${hours} hour${hours > 1 ? "s" : ""}`);
  if (minutes) parts.push(`${minutes} minute${minutes > 1 ? "s" : ""}`);

  return parts.length ? parts.join(", ") : "Less than 1 minute";
}

exports.submitAssignment = async (req, res) => {
  try {
    const { assignmentId, textAnswer } = req.body;

    if (!assignmentId) {
      return res.status(400).json({
        success: false,
        error: "assignmentId is required"
      });
    }

    const assignment = await Assignment.findById(assignmentId);

    if (!assignment) {
      return res.status(404).json({
        success: false,
        error: "Assignment not found"
      });
    }

    const existingSubmission = await Submission.findOne({
      student: req.user.userId,
      assignment: assignmentId
    });

    if (existingSubmission) {
      return res.status(400).json({
        success: false,
        error: "You already submitted this assignment."
      });
    }

    const submittedAt = new Date();
    const deadlineAt = assignment.dueDate ? new Date(assignment.dueDate) : null;

    let isLate = false;
    let lateByMs = 0;
    let lateByText = null;

    if (deadlineAt && submittedAt > deadlineAt) {
      isLate = true;
      lateByMs = submittedAt.getTime() - deadlineAt.getTime();
      lateByText = formatLateDuration(lateByMs);
    }

    const submission = new Submission({
      student: req.user.userId,
      assignment: assignmentId,
      textAnswer: textAnswer || null,
      fileUrl: req.file ? req.file.path : null,
      submittedAt,
      isLate,
      deadlineAt,
      lateByMs,
      lateByText
    });

    await submission.save();

    await Assignment.findByIdAndUpdate(assignmentId, {
      $addToSet: { submissions: submission._id }
    });

    res.json({
      success: true,
      message: isLate
        ? `Assignment submitted late by ${lateByText}.`
        : "Assignment submitted successfully.",
      data: submission
    });
  } catch (err) {
    console.error("Submit assignment error:", err);
    res.status(500).json({
      success: false,
      error: "Server error"
    });
  }
};


/* ========================
   ❓ Quizzes Protected Timer Logic
======================== */

const EXAM_SUBMIT_GRACE_MS = 10 * 1000;

function getStudentId(req) {
  return req.user.userId || req.user.id;
}

function getRemainingSeconds(attempt) {
  if (!attempt || !attempt.expiresAt) return null;

  const remaining = Math.ceil(
    (new Date(attempt.expiresAt).getTime() - Date.now()) / 1000
  );

  return Math.max(0, remaining);
}

async function expireAttemptIfNeeded(attempt) {
  if (!attempt) return null;

  if (
    attempt.status === "in_progress" &&
    attempt.expiresAt &&
    Date.now() > new Date(attempt.expiresAt).getTime()
  ) {
    attempt.status = "expired";
    await attempt.save();
  }

  return attempt;
}

function isTooLateToSubmit(attempt) {
  if (!attempt || !attempt.expiresAt) return false;

  return Date.now() > new Date(attempt.expiresAt).getTime() + EXAM_SUBMIT_GRACE_MS;
}

function buildSessionPayload(attempt) {
  const obj = attempt.toObject ? attempt.toObject() : attempt;

  return {
    ...obj,
    remainingSeconds: getRemainingSeconds(attempt),
    serverNow: new Date()
  };
}

exports.startQuiz = async (req, res) => {
  try {
    const { quizId } = req.params;
    const studentId = getStudentId(req);

    if (!quizId) {
      return res.status(400).json({
        success: false,
        error: "quizId is missing"
      });
    }

    const quiz = await Quiz.findById(quizId).select("title duration examType attempts");

    if (!quiz) {
      return res.status(404).json({
        success: false,
        error: "Quiz not found"
      });
    }

    let attempt = await QuizAttempt.findOne({
      quiz: quizId,
      student: studentId
    });

    if (attempt) {
      await expireAttemptIfNeeded(attempt);

      if (
        attempt.status === "pending" ||
        attempt.status === "reviewed" ||
        attempt.submittedAt
      ) {
        return res.status(409).json({
          success: false,
          error: "You already submitted this quiz. You cannot start it again.",
          attempt: buildSessionPayload(attempt)
        });
      }

      if (attempt.status === "expired") {
        return res.status(403).json({
          success: false,
          error: "Quiz time has ended. You cannot start this quiz again.",
          attempt: buildSessionPayload(attempt)
        });
      }

      return res.json({
        success: true,
        message: "Quiz already started. Continuing with remaining time.",
        data: buildSessionPayload(attempt)
      });
    }

    const now = new Date();
    const durationMinutes = Number(quiz.duration) || 20;
    const expiresAt = new Date(now.getTime() + durationMinutes * 60 * 1000);

    attempt = new QuizAttempt({
      quiz: quizId,
      student: studentId,
      status: "in_progress",
      startedAt: now,
      attemptedAt: now,
      expiresAt
    });

    await attempt.save();

    await Quiz.findByIdAndUpdate(quizId, {
      $addToSet: { attempts: attempt._id }
    });

    res.status(201).json({
      success: true,
      message: "Quiz started successfully.",
      data: buildSessionPayload(attempt)
    });
  } catch (err) {
    if (err.code === 11000) {
      return res.status(409).json({
        success: false,
        error: "Quiz attempt already exists. Please refresh and continue."
      });
    }

    console.error("Start quiz error:", err);
    res.status(500).json({
      success: false,
      error: "Server error"
    });
  }
};

exports.getMyQuizzes = async (req, res) => {
  try {
    const studentId = getStudentId(req);

    const user = await User.findById(studentId).populate({
      path: "paidCourses",
      populate: { path: "Quiz", model: "Quiz" }
    });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const attempts = await QuizAttempt.find({ student: studentId }).populate("quiz");
    const attemptsMap = {};

    for (const attempt of attempts) {
      if (!attempt.quiz) continue;

      await expireAttemptIfNeeded(attempt);

      attemptsMap[String(attempt.quiz._id)] = attempt;
    }

    const quizzes = [];

    user.paidCourses.forEach(course => {
      if (course && course.Quiz && Array.isArray(course.Quiz)) {
        course.Quiz.forEach(q => {
          if (!q) return;

          const attempt = attemptsMap[String(q._id)] || null;
          let attemptStatus = "not_started";

          if (attempt) {
            if (attempt.status === "reviewed") {
              attemptStatus = "reviewed";
            } else if (attempt.status === "pending" || attempt.submittedAt) {
              attemptStatus = "pending";
            } else if (attempt.status === "expired") {
              attemptStatus = "expired";
            } else {
              attemptStatus = "in_progress";
            }
          }

          quizzes.push({
            quizId: q._id,
            title: q.title,
            description: q.description,
            type: q.examType,
            examType: q.examType,
            duration: q.duration,
            totalMarks: q.totalMarks,

            attempted: !!attempt,
            attemptStatus,
            remainingSeconds: attempt ? getRemainingSeconds(attempt) : null,

            startedAt: attempt ? attempt.startedAt : null,
            expiresAt: attempt ? attempt.expiresAt : null,
            submittedAt: attempt ? attempt.submittedAt || attempt.createdAt : null,

            score: attempt ? attempt.score : null,
            feedback: attempt ? attempt.feedback : null,
            reviewedAt: attempt ? attempt.reviewedAt : null
          });
        });
      }
    });

    res.json({
      success: true,
      data: quizzes
    });
  } catch (err) {
    console.error("Get my quizzes error:", err);
    res.status(500).json({ error: "Server error" });
  }
};

exports.getQuiz = async (req, res) => {
  try {
    const quiz = await Quiz.findById(req.params.id).populate("questions");

    if (!quiz) {
      return res.status(404).json({ error: "Quiz not found" });
    }

    res.json(quiz);
  } catch (error) {
    console.error("Get quiz error:", error);
    res.status(500).json({ error: "Failed to fetch quiz" });
  }
};

exports.getUserQuizAttempt = async (req, res) => {
  try {
    const { quizId } = req.params;
    const studentId = getStudentId(req);

    const attempt = await QuizAttempt.findOne({
      quiz: quizId,
      student: studentId
    });

    if (!attempt) {
      return res.json({
        success: true,
        attempt: null
      });
    }

    await expireAttemptIfNeeded(attempt);

    res.json({
      success: true,
      attempt: buildSessionPayload(attempt)
    });
  } catch (err) {
    console.error("Get user quiz attempt error:", err);
    res.status(500).json({ error: "Failed to get quiz attempt" });
  }
};

exports.submitQuiz = async (req, res) => {
  try {
    const { quizId } = req.params;
    const { answers = [], pendingTime } = req.body;
    const studentId = getStudentId(req);

    if (!quizId) {
      return res.status(400).json({ error: "quizId is missing" });
    }

    const quiz = await Quiz.findById(quizId).populate("questions");

    if (!quiz) {
      return res.status(404).json({ error: "Quiz not found" });
    }

    const attempt = await QuizAttempt.findOne({
      quiz: quizId,
      student: studentId
    });

    if (!attempt) {
      return res.status(400).json({
        error: "You must start the quiz first."
      });
    }

    if (
      attempt.status === "pending" ||
      attempt.status === "reviewed" ||
      attempt.submittedAt
    ) {
      return res.status(400).json({
        error: "You already submitted this quiz."
      });
    }

    if (attempt.status === "expired" || isTooLateToSubmit(attempt)) {
      attempt.status = "expired";
      await attempt.save();

      return res.status(403).json({
        error: "Quiz time has ended. Submission is closed."
      });
    }

    const answersByQuestionId = new Map();

    answers.forEach(a => {
      const questionId = a.questionId || a.question;

      if (questionId) {
        answersByQuestionId.set(String(questionId), a.answer || "");
      }
    });

    const mappedAnswers = quiz.questions.map((question, index) => {
      const questionId = String(question._id);

      const answer = answersByQuestionId.has(questionId)
        ? answersByQuestionId.get(questionId)
        : answers[index]?.answer || "";

      return {
        question: question._id,
        answer,
        marksObtained: 0,
        isCorrect: false
      };
    });

    attempt.answers = mappedAnswers;
    attempt.status = "pending";
    attempt.submittedAt = new Date();

    if (pendingTime) {
      attempt.pendingUntil = new Date(
        Date.now() + Number(pendingTime) * 60 * 1000
      );
    }

    await attempt.save();

    await Quiz.findByIdAndUpdate(quizId, {
      $addToSet: { attempts: attempt._id }
    });

    res.json({
      success: true,
      message: "Quiz submitted successfully.",
      data: attempt
    });
  } catch (err) {
    console.error("Submit quiz error:", err);
    res.status(500).json({ error: "Server error" });
  }
};

async function savePdfSubmission(req, res, quizId) {
  const studentId = getStudentId(req);

  if (!quizId) {
    return res.status(400).json({ error: "quizId is required" });
  }

  if (!req.file) {
    return res.status(400).json({ error: "Answer file is required" });
  }

  const attempt = await QuizAttempt.findOne({
    quiz: quizId,
    student: studentId
  });

  if (!attempt) {
    return res.status(400).json({
      error: "You must start the quiz first."
    });
  }

  if (
    attempt.status === "pending" ||
    attempt.status === "reviewed" ||
    attempt.submittedAt
  ) {
    return res.status(400).json({
      error: "You already submitted this quiz."
    });
  }

  if (attempt.status === "expired" || isTooLateToSubmit(attempt)) {
    attempt.status = "expired";
    await attempt.save();

    return res.status(403).json({
      error: "Quiz time has ended. Upload is closed."
    });
  }

  attempt.pdfAnswerFile = req.file.path;
  attempt.status = "pending";
  attempt.submittedAt = new Date();

  await attempt.save();

  await Quiz.findByIdAndUpdate(quizId, {
    $addToSet: { attempts: attempt._id }
  });

  return res.json({
    success: true,
    message: "Answer file uploaded successfully.",
    attempt
  });
}

exports.uploadQuizAnswer = async (req, res) => {
  try {
    return await savePdfSubmission(req, res, req.params.quizId);
  } catch (err) {
    console.error("Upload quiz answer error:", err);
    res.status(500).json({ error: "Server error" });
  }
};

exports.submitPdfQuiz = async (req, res) => {
  try {
    return await savePdfSubmission(req, res, req.body.quizId);
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
    const sessions = await LiveSession.find({
      course: { $in: req.user.paidCourses }
    });

    res.json({
      success: true,
      data: sessions
    });
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

    res.json({
      compilerAccess: student.hasCompilerAccess
    });
  } catch (err) {
    console.error("Get compiler access error:", err);
    res.status(500).json({ error: "Server error" });
  }
};
