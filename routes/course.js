const express = require('express');
const router = express.Router();
const Course = require('../models/Course');
const User = require('../models/User');
const authenticate = require('../middleware/auth'); // JWT auth middleware

// Buy course
router.post('/buy/:courseId', authenticate, async (req, res) => {
  try {
    const userId = req.user.userId;
    const courseId = req.params.courseId;

    const user = await User.findById(userId);
    if (user.paidCourses.includes(courseId)) {
      return res.status(400).json({ message: 'Already purchased this course' });
    }

    user.paidCourses.push(courseId);
    await user.save();

    res.json({ message: 'Course purchased successfully' });
  } catch (err) {
    console.error('Buy error:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

module.exports = router;
