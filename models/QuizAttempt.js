// models/QuizAttempt.js
const mongoose = require("mongoose");

const quizAttemptSchema = new mongoose.Schema({
  quiz: { type: mongoose.Schema.Types.ObjectId, ref: "Quiz", required: true },
  student: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  answers: [
    {
      question: { type: mongoose.Schema.Types.ObjectId, ref: "Question" },
      answer: String, // student’s answer
      isCorrect: Boolean,
      marksObtained: { type: Number, default: 0 }
    }
  ],
  pdfAnswerFile: { type: String },
  score: { type: Number, default: 0 },
  feedback: { type: String },
reviewedAt: { type: Date },
  status: { type: String, enum: ['pending', 'reviewed'], default: 'pending' },
  attemptedAt: { type: Date, default: Date.now },
  pendingUntil: { type: Date },
}, { timestamps: true });

module.exports = mongoose.model("QuizAttempt", quizAttemptSchema);
