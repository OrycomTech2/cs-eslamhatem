// controllers/roomController.js
const jwt = require('jsonwebtoken');
const generateTurnCredentials = require('../utils/turnCreds');
const LiveSession = require('../models/LiveSession');
const Course = require('../models/Course');

exports.requestJoinToken = async (req, res) => {
  try {
    const { sessionId } = req.body;
    const userId = req.user._id;

    // 1. Validate session exists & is active
    const session = await LiveSession.findById(sessionId).populate('course');
    if (!session || !session.isActive) return res.status(404).json({ message: 'Session not active' });

    // 2. Verify access: instructor OR enrolled student
    const isInstructor = session.instructor.toString() === userId.toString();
    const isEnrolled = session.course && session.course.students && session.course.students.some(s => s.toString() === userId.toString()); 
    // adapt to your Course model's enrollment field (paidCourses, etc.)
    if (!isInstructor && !isEnrolled) return res.status(403).json({ message: 'Not enrolled' });

    // 3. Issue ephemeral room token
    const payload = {
      sessionId,
      userId,
      role: isInstructor ? 'instructor' : 'student'
    };
    const token = jwt.sign(payload, process.env.ROOM_TOKEN_SECRET, { expiresIn: Number(process.env.ROOM_TOKEN_TTL || 3600) });

    // 4. Generate TURN creds
    const turnCreds = generateTurnCredentials({
      usernamePrefix: `u_${userId}_`,
      ttl: Number(process.env.TURN_USER_TTL || 3600),
      secret: process.env.TURN_SECRET,
      realm: process.env.TURN_DOMAIN
    });

    res.json({
      roomToken: token,
      expiresIn: Number(process.env.ROOM_TOKEN_TTL || 3600),
      turn: {
        urls: [
          `turn:${process.env.TURN_DOMAIN}:${process.env.TURN_PORT}`,
          `turns:${process.env.TURN_DOMAIN}:5349`
        ],
        username: turnCreds.username,
        credential: turnCreds.credential,
        realm: turnCreds.realm
      }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: err.message });
  }
};
