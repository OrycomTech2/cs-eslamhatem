// models/Lesson.js
const mongoose = require('mongoose');

const quizSchema = new mongoose.Schema({
  type: {
    type: String,
    enum: ['multiple_choice', 'true_false', 'fill_blank'], // ✅ Must match input exactly
    required: true
  },
  question: { type: String, required: true },
  options: [String], // optional for true/false
  correctAnswer: { type: String, required: true }
});

const assignmentSchema = new mongoose.Schema({
  
  question: { type: String, required: true },
  dueDate: { type: Date, required: true }
});

const lessonSchema = new mongoose.Schema({
  course: { type: mongoose.Schema.Types.ObjectId, ref: 'Course', required: true },
  title: { type: String, required: true },
  thumbnail: String,
  video: String,
  pdf: String,
  description: String,
  duration: { type: Number, required: true },
  quizzes: [quizSchema],
  assignments: [assignmentSchema]
}, { timestamps: true });

module.exports = mongoose.model('Content', lessonSchema);
