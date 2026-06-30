// models/Assignment.js
const mongoose = require("mongoose");

const assignmentSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: { type: String },

  // ✅ This stores full deadline: date + time
  // Example: 2026-07-01T20:30:00.000Z
  dueDate: { type: Date, required: true },

  grade: { type: Number },
  feedback: { type: String },

  reviewedBy: { 
    type: mongoose.Schema.Types.ObjectId,
    refPath: "reviewerModel"
  },

  reviewerModel: {
    type: String,
    enum: ["Admin", "Assistant"]
  },

  reviewedAt: { type: Date },

  course: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Course",
    required: true
  },

  pdf: { type: String },

  submissions: [{ type: mongoose.Schema.Types.ObjectId, ref: "Submission" }],
}, { timestamps: true });

module.exports = mongoose.model("Assignment", assignmentSchema);
