const express = require('express');
const router = express.Router();
const multer = require('multer');
const Instructor = require('../models/Instructor');
const instructorController = require('../controllers/instructorController');
const authenticate = require("../middleware/authenticate");


const upload = multer({ dest: 'uploads/' });

router.get('/getinstructor', instructorController.getInstructor);
router.post('/addinstructor', upload.single('photo'), instructorController.addInstructor);
router.put('/:id', upload.single('photo'), instructorController.updateInstructor);

router.get('/', async (req, res) => {
  try {
    const instructors = await Instructor.find({}, '_id name'); // only send needed fields
    res.json({ data: instructors });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});


// ✅ Get courses by instructor ID
router.get('/courses/:instructorId', async (req, res) => {
  try {
    const { instructorId } = req.params;
    const courses = await Course.find({ instructor: instructorId }, '_id title');
    res.status(200).json({ data: courses });
  } catch (err) {
    console.error('Error fetching courses:', err);
    res.status(500).json({ message: 'Server error while fetching courses.' });
  }
});

router.get("/profile", authenticate, instructorController.getInstructorProfile);
router.put("/update-info", authenticate, instructorController.updateInstructorInfo);
router.put("/update-photo", authenticate, upload.single("photo"), instructorController.updateInstructorPhoto);
router.put("/change-password", authenticate, instructorController.changeInstructorPassword);

module.exports = router;
