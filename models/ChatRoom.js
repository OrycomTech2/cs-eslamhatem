// models/ChatRoom.js
const mongoose = require('mongoose');

const participantSchema = new mongoose.Schema({
  role: { type: String, enum: ['user', 'instructor', 'admin'], required: true },
  refId: { type: mongoose.Schema.Types.ObjectId, required: true }, // ID from its own collection
  displayName: { type: String, required: true },
  photo: String,
}, { _id: false });

const chatRoomSchema = new mongoose.Schema({
  type: { type: String, enum: ['general', 'dm', 'group'], default: 'dm' },
  title: String, // optional for general/group
  participants: [participantSchema],
  lastMessageAt: { type: Date, default: Date.now },
}, { timestamps: true });

chatRoomSchema.index({ 'participants.role': 1, 'participants.refId': 1 });
chatRoomSchema.index({ lastMessageAt: -1 });

module.exports = mongoose.model('ChatRoom', chatRoomSchema);
