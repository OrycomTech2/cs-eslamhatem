// routes/assignmentRoutes.js
const express = require('express');
const router = express.Router();
const auth = require('../middleware/auth');
const Content = require('../models/Content');
const User = require('../models/User');
const multer = require('multer');
const path = require('path');

// File upload config
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/assignments'),
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname));
  }
});
const upload = multer({ storage });

// Get assignments for logged-in student
router.get('/my-assignments', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).populate('paidCourses');
    if (!user) return res.status(404).json({ error: 'User not found' });

    const courseIds = user.paidCourses.map(c => c._id);
    const assignments = await Content.find({
      course: { $in: courseIds },
      assignments: { $exists: true, $ne: [] }
    });

    res.json(assignments);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Submit assignment
router.post('/submit/:assignmentId', auth, upload.single('file'), async (req, res) => {
  try {
    // Here you would store in DB or mark submission
    res.json({
      message: 'Assignment submitted successfully',
      file: req.file.filename
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Submission failed' });
  }
});

module.exports = router;
