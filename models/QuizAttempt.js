// models/QuizAttempt.js
const mongoose = require("mongoose");

const quizAttemptSchema = new mongoose.Schema(
  {
    quiz: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Quiz",
      required: true
    },

    student: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true
    },

    answers: [
      {
        question: {
          type: mongoose.Schema.Types.ObjectId,
          ref: "Question"
        },
        answer: String,
        isCorrect: Boolean,
        marksObtained: {
          type: Number,
          default: 0
        }
      }
    ],

    pdfAnswerFile: {
      type: String
    },

    score: {
      type: Number,
      default: 0
    },

    totalMarks: {
      type: Number,
      default: 0
    },

    feedback: {
      type: String
    },

    reviewedAt: {
      type: Date
    },

    status: {
      type: String,
      enum: ["in_progress", "pending", "reviewed", "expired"],
      default: "in_progress"
    },

    // When student first starts the quiz
    startedAt: {
      type: Date
    },

    // Real server-side quiz end time
    expiresAt: {
      type: Date
    },

    // When student submits/upload answers
    submittedAt: {
      type: Date
    },

    // Keep your old field for compatibility
    attemptedAt: {
      type: Date,
      default: Date.now
    },

    pendingUntil: {
      type: Date
    }
  },
  { timestamps: true }
);

// Important: one student = one attempt per quiz
quizAttemptSchema.index({ quiz: 1, student: 1 }, { unique: true });

module.exports = mongoose.model("QuizAttempt", quizAttemptSchema);
