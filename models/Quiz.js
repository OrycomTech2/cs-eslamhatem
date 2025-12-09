// models/Quiz.js
const mongoose = require("mongoose");

const quizSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: { type: String },
  course: { type: mongoose.Schema.Types.ObjectId, ref: "Course", required: true },
  questions: [{ type: mongoose.Schema.Types.ObjectId, ref: "Question" }],
  duration: { type: Number }, // in minutes
  totalMarks: { type: Number, default: 0 },
  attempts: [{ type: mongoose.Schema.Types.ObjectId, ref: "QuizAttempt" }],
  examType: { type: String, enum: ['structured', 'pdf'], default: 'structured' },
  pdfFile: { type: String }, // Path to the uploaded PDF file
}, { timestamps: true });

module.exports = mongoose.model("Quiz", quizSchema);