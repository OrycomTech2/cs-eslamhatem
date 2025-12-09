// models/Message.js
const mongoose = require('mongoose');

const messageSchema = new mongoose.Schema({
  room: { type: mongoose.Schema.Types.ObjectId, ref: 'ChatRoom', required: true },
  senderRole: { type: String, enum: ['user', 'instructor', 'admin'], required: true },
  senderId: { type: mongoose.Schema.Types.ObjectId, required: true },
  senderName: { type: String, required: true },
  text: { type: String, default: '' },
  attachments: [{
    url: String,
    name: String,
    size: Number,
    mime: String,
  }],
  readBy: [{
    role: { type: String, enum: ['user', 'instructor', 'admin'] },
    refId: mongoose.Schema.Types.ObjectId,
    readAt: Date
  }]
}, { timestamps: true });

messageSchema.index({ room: 1, createdAt: -1 });

module.exports = mongoose.model('Message', messageSchema);
