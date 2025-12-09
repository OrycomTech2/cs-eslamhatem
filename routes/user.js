const express = require('express');
const router = express.Router();
const { getAllUsers } = require('../controllers/userController');
const {
  getProfile,
  getMyCourses,
  enrollUserInCourse  // ✅ FIX: use correct function name
} = require('../controllers/userController');

const authMiddleware = require('../middleware/auth');  // ✅ auth middleware

router.get('/profile', authMiddleware, getProfile);
router.get('/my-courses', authMiddleware, getMyCourses);
router.post('/enroll/:courseId', authMiddleware, enrollUserInCourse); // ✅ FIXED!
router.get('/', getAllUsers);



module.exports = router;
