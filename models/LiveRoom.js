const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const LiveRoomSchema = new Schema({
  course: { type: Schema.Types.ObjectId, ref: 'Course', required: true },
  teacher: { type: Schema.Types.ObjectId, ref: 'User', required: true },
  title: { type: String, default: 'Live Session' },
  status: { type: String, enum: ['live', 'ended', 'scheduled'], default: 'live' },
  participants: [{ user: { type: Schema.Types.ObjectId, ref: 'User' }, joinedAt: Date }],
  startedAt: Date,
  endedAt: Date
}, { timestamps: true });

module.exports = mongoose.model('LiveRoom', LiveRoomSchema);