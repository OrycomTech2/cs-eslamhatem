const express = require('express');
const router = express.Router();
const multer = require('multer');
const path = require('path');
const { getMyAssignments, submitAssignment, getMySubmissions } = require("../controllers/contentController");
const auth = require("../middleware/auth");


// Configure multer for uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/'); // Ensure this folder exists
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const ext = path.extname(file.originalname);
    cb(null, uniqueSuffix + ext);
  }
});



const upload = multer({ storage });

// ✅ Import your controller function (make sure the path is correct)
const { uploadInstructorContent } = require('../controllers/contentController');

// ✅ Define route
router.post('/instructor/upload', upload.single('file'), uploadInstructorContent);

router.get("/my-assignments", auth, getMyAssignments);
router.post("/submit-assignment/:id", auth, upload.single("assignmentFile"), submitAssignment);
router.get("/my-submissions", auth, getMySubmissions);

module.exports = router;
