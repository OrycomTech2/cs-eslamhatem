// models/Course.js
const mongoose = require("mongoose");

const courseSchema = new mongoose.Schema({
  title: { type: String, required: true, trim: true },
  description: { type: String },
  thumbnail: { type: String },
  price: { type: Number, default: 0 },
  isFree: { type: Boolean, default: false },
  type: { 
    type: String, 
    enum: ["Theoretical", "Practical"], 
    required: true 
  },
  duration: { type: Number }, // in hours
  instructor: { type: mongoose.Schema.Types.ObjectId, ref: "Admin", required: true },
  assistants: [{ type: mongoose.Schema.Types.ObjectId, ref: "Assistant" }],
  students: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
  lessons: [{ type: mongoose.Schema.Types.ObjectId, ref: "Lesson" }],
  assignments: [{ type: mongoose.Schema.Types.ObjectId, ref: "Assignment" }],
  Quiz: [{ type: mongoose.Schema.Types.ObjectId, ref: "Quiz" }],
  compilerAccess: { type: Boolean, default: false },
  liveSessions: [{ type: mongoose.Schema.Types.ObjectId, ref: "LiveSession" }],
}, { timestamps: true });

module.exports = mongoose.model("Course", courseSchema);
