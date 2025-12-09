// models/SubscriptionCode.js
const mongoose = require("mongoose");

const subscriptionCodeSchema = new mongoose.Schema({
  code: { type: String, required: true, unique: true },
  package: { type: mongoose.Schema.Types.ObjectId, ref: "Package", required: true },
  used: { type: Boolean, default: false },
  usedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" }
}, { timestamps: true });

module.exports = mongoose.model("SubscriptionCode", subscriptionCodeSchema);
