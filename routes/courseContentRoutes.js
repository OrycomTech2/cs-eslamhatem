const express = require('express');
const router = express.Router();
const lessonController = require('../controllers/lessonController');
const uploadLessonFiles = require('../middleware/upload');
const upload = require('../middleware/upload');
const {
  createCourse,
  getAllCourses,
  getCourse,
  buyCourse,
  enrollFreeCourse
} = require('../controllers/courseController');


router.get('/instructor/:instructorId', async (req, res) => {
  try {
    const { instructorId } = req.params;
    const courses = await Course.find({ instructor: instructorId });
    res.json({ data: courses });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 🟢 Create Course (with thumbnail upload)
router.post('/create', upload.single('thumbnail'), createCourse);

// 🟢 Get all courses
router.get('/', getAllCourses);

// 🟢 Get one course by ID
router.get('/:id', getCourse);

// 🟢 Purchase course (for paid)
router.post('/buy/:courseId', buyCourse);

// 🟢 Enroll in free course
router.post('/enroll/:id', enrollFreeCourse);

router.post('/:courseId/lessons',
  upload.fields([
    { name: 'video', maxCount: 1 },
    { name: 'pdf', maxCount: 10 },
    { name: 'thumbnail', maxCount: 1 }
  ]),
  lessonController.createLesson
);


module.exports = router;
