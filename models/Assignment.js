// models/Assignment.js
const mongoose = require("mongoose");

const assignmentSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: { type: String },
  dueDate: { type: Date },
    grade: { type: Number },
  feedback: { type: String },
  reviewedBy: { 
    type: mongoose.Schema.Types.ObjectId,
    refPath: "reviewerModel"   // 👈 dynamic ref
  },
  reviewerModel: {             // 👈 tells mongoose which collection to use
    type: String,
    enum: ["Admin", "Assistant"]
  },  reviewedAt: { type: Date }, // ✅ review date
  course: { type: mongoose.Schema.Types.ObjectId, ref: "Course", required: true },
    pdf: { type: String }, // ✅ store filename/path of uploaded PDF
  submissions: [{ type: mongoose.Schema.Types.ObjectId, ref: "Submission" }],
}, { timestamps: true });

module.exports = mongoose.model("Assignment", assignmentSchema);
