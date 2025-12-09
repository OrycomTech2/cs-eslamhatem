// routes/liveRoutes.js
const express = require('express');
const { AccessToken } = require('livekit-server-sdk');
const { LIVEKIT_API_KEY, LIVEKIT_API_SECRET } = require('../config/livekit');
const LiveRoom = require('../models/LiveRoom');
const auth = require('../middleware/auth'); // middleware تحقق JWT من نظامك
const router = express.Router();


router.get('/status/course/:courseId', async (req, res) => {
  try {
    const { courseId } = req.params;
    const liveRoom = await LiveRoom.findOne({ course: courseId, status: 'live' });
    if (!liveRoom) {
      return res.status(404).json({ message: 'No live session found for this course' });
    }
    res.json({ isLive: true, sessionId: liveRoom._id });
  } catch (err) {
    console.error('Error fetching live session status:', err);
    res.status(500).json({ message: 'Failed to fetch live session status' });
  }
});
// مدرس يبدأ جلسة
router.post('/create', auth, async (req, res) => {
  try {
    const { courseId, title } = req.body;
    // تحقق أن المستخدم مدرس ويمتلك الكورس
    if (req.user.role !== 'teacher') return res.status(403).json({ error: 'Access denied' });

    const room = await LiveRoom.create({
      course: courseId,
      teacher: req.user.id,
      title,
      status: 'live',
      startedAt: new Date()
    });

    res.json({ roomId: room._id });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// الحصول على توكن لدخول البث
router.get('/token/:roomId', auth, async (req, res) => {
  try {
    const room = await LiveRoom.findById(req.params.roomId);
    if (!room) return res.status(404).json({ error: 'Room not found' });

    // تحقق أن الطالب مسموح له يدخل
    if (req.user.role === 'student') {
      const hasCourse = req.user.paidCourses.some(c => c.toString() === room.course.toString());
      if (!hasCourse) return res.status(403).json({ error: 'You are not enrolled in this course' });
    }

    // إنشاء توكن
    const at = new AccessToken(LIVEKIT_API_KEY, LIVEKIT_API_SECRET, {
      identity: req.user.id.toString(),
      name: req.user.name
    });
    at.addGrant({
      roomJoin: true,
      room: room._id.toString(),
      canPublish: req.user.role === 'teacher',
      canSubscribe: true
    });

    res.json({ token: at.toJwt(), url: LIVEKIT_URL });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
