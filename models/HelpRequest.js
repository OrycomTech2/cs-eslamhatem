// models/HelpRequest.js
const mongoose = require("mongoose");

const helpRequestSchema = new mongoose.Schema({
  sender: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true }, // could also ref Instructor
  role: { type: String, enum: ["student", "instructor"], required: true },
  subject: { type: String, required: true },
  message: { type: String, required: true },
  attachment: { type: String }, // file (screenshot, pdf, etc.)
  status: { type: String, enum: ["pending", "in-progress", "resolved"], default: "pending" },
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model("HelpRequest", helpRequestSchema);
