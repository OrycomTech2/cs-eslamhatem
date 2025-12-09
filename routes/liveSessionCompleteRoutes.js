const express = require('express');
const router = express.Router();
const { startSession, endLiveSession, sendLiveTask, requestJoinToken } = require('../controllers/liveSessionController');
const auth = require('../middleware/auth');

// Live session management endpoints
router.post('/start-session', auth, startSession);
router.post('/end-session/:sessionId', auth, endLiveSession);
router.post('/token', auth, requestJoinToken);

// Additional endpoints for complete functionality
router.get('/status/course/:courseId', async (req, res) => {
  try {
    const { courseId } = req.params;
    const LiveSession = require('../models/LiveSession');
    
    const session = await LiveSession.findOne({ 
      course: courseId, 
      active: true 
    }).populate('course');
    
    if (!session) {
      return res.status(404).json({ 
        message: 'No active live session found for this course' 
      });
    }
    
    res.json({ 
      isLive: true, 
      sessionId: session._id,
      courseId: session.course._id,
      title: session.title || 'Live Session',
      instructor: session.instructor
    });
  } catch (err) {
    console.error('Error fetching live session status:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Health check endpoint
router.get('/health', (req, res) => {
  res.json({ status: 'OK', service: 'Live Session API' });
});

module.exports = router;
