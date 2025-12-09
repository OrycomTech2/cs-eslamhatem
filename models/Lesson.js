const mongoose = require("mongoose");

const lessonSchema = new mongoose.Schema({
  title: { type: String, required: true, trim: true },
  description: { type: String },
  type: { type: String, enum: ["Theoretical", "Practical"], required: true },
  price: { type: Number, default: 0 },

  // Uploaded files
  material: { type: String },   // PDF or docs
  video: { type: String },      // video file path
  thumbnail: { type: String },  // image

  course: { type: mongoose.Schema.Types.ObjectId, ref: "Course", required: true },

  // Relations
  assignments: [{ type: mongoose.Schema.Types.ObjectId, ref: "Assignment" }],
  quizzes: [{ type: mongoose.Schema.Types.ObjectId, ref: "Quiz" }],
}, { timestamps: true });

module.exports = mongoose.model("Lesson", lessonSchema);
