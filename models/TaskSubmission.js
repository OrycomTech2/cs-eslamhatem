// models/TaskSubmission.js
const mongoose = require("mongoose");

const taskSubmissionSchema = new mongoose.Schema({
  student: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  task: { type: mongoose.Schema.Types.ObjectId, ref: "Task" }, // optional
  roomId: { type: String }, // if from live session
    student: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },

  course: { type: mongoose.Schema.Types.ObjectId, ref: "Course" }, // optional
  content: { type: String, required: true }, // answer or text
  fileUrl: { type: String }, // optional uploaded file
  status: { type: String, enum: ["pending", "approved", "rejected"], default: "pending" },
  feedback: { type: String },
    reviewedBy: { type: mongoose.Schema.Types.ObjectId, ref: "Admin" },

}, { timestamps: true });

module.exports = mongoose.model("TaskSubmission", taskSubmissionSchema);
