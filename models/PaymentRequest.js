const mongoose = require("mongoose");

const paymentRequestSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },

  // Either course OR lesson will be used
  course: { type: mongoose.Schema.Types.ObjectId, ref: "Course" },
  lesson: { type: mongoose.Schema.Types.ObjectId, ref: "Lesson" },

  amount: { type: Number, required: true },
  method: {
    type: String,
    enum: ["orange_cash", "etisalat_cash", "vodafone_cash", "instapay"],
    required: true
  },
  walletId: { type: String, required: true },
  screenshotUrl: String,

  status: {
    type: String,
    enum: ["pending", "approved", "rejected"],
    default: "pending"
  },
  PhoneNumber: String,

  processedBy: { type: mongoose.Schema.Types.ObjectId, ref: "Admin" },
  processedAt: Date,
  rejectionReason: String,
}, { timestamps: true });

module.exports = mongoose.model("PaymentRequest", paymentRequestSchema);
