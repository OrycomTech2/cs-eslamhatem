// models/AssignmentSubmission.js
const mongoose = require("mongoose");

const assignmentSubmissionSchema = new mongoose.Schema({
  assignmentId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Content.assignments", // links to assignment inside a lesson
    required: true
  },
  lessonId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Content",
    required: true
  },
  courseId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Course",
    required: true
  },
  studentId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true
  },
  fileUrl: {
    type: String, // saved file path or S3/Cloudinary link
    required: true
  },
submittedAt: {
  type: Date,
  default: Date.now
},

isLate: {
  type: Boolean,
  default: false
},

deadlineAt: {
  type: Date,
  default: null
},

lateByMs: {
  type: Number,
  default: 0
},

lateByText: {
  type: String,
  default: null
},
  status: {
    type: String,
    enum: ["submitted", "graded"],
    default: "submitted"
  },
  grade: {
    type: Number, // optional if you want instructors to grade
    default: null
  },
  feedback: {
    type: String
  }
});

module.exports = mongoose.model("AssignmentSubmission", assignmentSubmissionSchema);
