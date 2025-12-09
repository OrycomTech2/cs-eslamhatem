const mongoose = require("mongoose");

const videoSchema = new mongoose.Schema({
  title: { type: String, required: true },   // the custom name you enter
  url: { type: String, required: true },     // R2 final URL
  size: { type: Number },                    // optional – filesize
  contentType: { type: String },             // optional – video/mp4 etc
  uploadedBy: { type: mongoose.Schema.Types.ObjectId, ref: "Admin" }, // optional
}, { timestamps: true });

module.exports = mongoose.model("Video", videoSchema);
