// controllers/chatController.js
const ChatRoom = require('../models/ChatRoom');
const Message = require('../models/Message');
const User = require('../models/User');
const Instructor = require('../models/Instructor');
const Admin = require('../models/Admin');

function roleToModel(role) {
  return role === 'user' ? User : role === 'instructor' ? Instructor : Admin;
}

exports.ensureGeneralRoom = async (req, res) => {
  // one shared "General" room for everyone
  let room = await ChatRoom.findOne({ type: 'general' });
  if (!room) {
    room = await ChatRoom.create({
      type: 'general',
      title: 'General',
      participants: [], // dynamic; members join via socket or when listing rooms
    });
  }
  res.json({ roomId: room._id, title: room.title });
};

exports.getMyRooms = async (req, res) => {
  const { role, id, name, photo } = req.principal;

  // ensure they are present in general room participants once accessed
  let general = await ChatRoom.findOne({ type: 'general' });
  if (general && !general.participants.some(p => p.refId.equals(id) && p.role === role)) {
    general.participants.push({ role, refId: id, displayName: name, photo });
    await general.save();
  }

  const rooms = await ChatRoom.find({
    participants: { $elemMatch: { role, refId: id } }
  }).sort({ lastMessageAt: -1 }).lean();

  res.json({ rooms });
};

exports.ensureDMRoom = async (req, res) => {
  const me = req.principal;
  const { targetRole, targetId } = req.body;

  if (!['user', 'instructor', 'admin'].includes(targetRole)) {
    return res.status(400).json({ error: 'Invalid targetRole' });
  }

  // Load target basic info
  const TargetModel = roleToModel(targetRole);
  const target = await TargetModel.findById(targetId).select('_id name photo');
  if (!target) return res.status(404).json({ error: 'Target not found' });

  // Find or create DM room
  let room = await ChatRoom.findOne({
    type: 'dm',
    'participants.role': { $all: [me.role, targetRole] },
    $and: [
      { 'participants': { $elemMatch: { role: me.role, refId: me.id } } },
      { 'participants': { $elemMatch: { role: targetRole, refId: target._id } } },
    ]
  });

  if (!room) {
    room = await ChatRoom.create({
      type: 'dm',
      participants: [
        { role: me.role, refId: me.id, displayName: me.name, photo: me.photo },
        { role: targetRole, refId: target._id, displayName: target.name, photo: target.photo || null },
      ],
      lastMessageAt: new Date(),
    });
  }

  res.json({ roomId: room._id });
};

exports.getMessages = async (req, res) => {
  const { roomId } = req.params;
  const { before, limit = 30 } = req.query;
  const me = req.principal;

  // Access check
  const room = await ChatRoom.findById(roomId);
  if (!room) return res.status(404).json({ error: 'Room not found' });
  const member = room.participants.some(p => p.role === me.role && p.refId.equals(me.id));
  if (!member && room.type !== 'general') return res.status(403).json({ error: 'Access denied' });

  const query = { room: roomId };
  if (before) query.createdAt = { $lt: new Date(before) };

  const messages = await Message.find(query)
    .sort({ createdAt: -1 })
    .limit(Math.min(+limit, 100))
    .lean();

  res.json({ messages: messages.reverse() });
};

exports.postMessage = async (req, res) => {
  const me = req.principal;
  const { roomId } = req.params;
  const { text, attachments = [] } = req.body;

  const room = await ChatRoom.findById(roomId);
  if (!room) return res.status(404).json({ error: 'Room not found' });

  // Must be a participant OR room is general
  const member = room.participants.some(p => p.role === me.role && p.refId.equals(me.id));
  if (!member && room.type !== 'general') return res.status(403).json({ error: 'Access denied' });

  const msg = await Message.create({
    room: room._id,
    senderRole: me.role,
    senderId: me.id,
    senderName: me.name,
    text: text || '',
    attachments,
  });

  room.lastMessageAt = new Date();
  // ensure in general room the sender shows in participants
  if (room.type === 'general' && !member) {
    room.participants.push({ role: me.role, refId: me.id, displayName: me.name, photo: me.photo });
  }
  await room.save();

  // Emit via socket (server will broadcast)
  req.app.get('io').to(room._id.toString()).emit('chat:message', {
    roomId: room._id.toString(),
    message: {
      _id: msg._id,
      text: msg.text,
      senderRole: msg.senderRole,
      senderId: msg.senderId,
      senderName: msg.senderName,
      attachments: msg.attachments,
      createdAt: msg.createdAt
    }
  });

  res.status(201).json({ ok: true, message: msg });
};
