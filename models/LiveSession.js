// models/LiveSession.js
const mongoose = require("mongoose");

const liveSessionSchema = new mongoose.Schema({
  course: { type: mongoose.Schema.Types.ObjectId, ref: "Course", required: true },
  title: { type: String, required: true },
  description: { type: String },
  scheduledAt: { type: Date, required: true },
  duration: { type: Number }, // in minutes
}, { timestamps: true });

module.exports = mongoose.model("LiveSession", liveSessionSchema);
