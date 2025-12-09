// models/Submission.js
const mongoose = require("mongoose");
const submissionSchema = new mongoose.Schema({
  student: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  assignment: { type: mongoose.Schema.Types.ObjectId, ref: "Assignment" },
  quiz: { type: mongoose.Schema.Types.ObjectId, ref: "Quiz" },
  fileUrl: { type: String },
  textAnswer: { type: String },
  grade: { type: Number },
  feedback: { type: String },
  reviewedAt: { type: Date }
}, { timestamps: true });


module.exports = mongoose.model("Submission", submissionSchema);
