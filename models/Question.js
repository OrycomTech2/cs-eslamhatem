// models/Question.js
const mongoose = require("mongoose");

const questionSchema = new mongoose.Schema({
  quiz: { type: mongoose.Schema.Types.ObjectId, ref: "Quiz", required: true },
  text: { type: String, required: true },
  type: { 
    type: String, 
    enum: ["mcq", "truefalse", "short"], 
    default: "mcq" 
  },
  options: [{ type: String }], // only for MCQ
  correctAnswer: { type: String }, // or index of correct option
  marks: { type: Number, default: 1 },
  totalMarks: { type: Number, default: 1 },
}, { timestamps: true });

module.exports = mongoose.model("Question", questionSchema);
