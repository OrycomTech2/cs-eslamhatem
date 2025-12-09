const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs'); // Add this
const router = express.Router();
const courseController = require('../controllers/courseController');
const authenticate = require('../middleware/authenticate');
// In upload.js




const fileFilter = (req, file, cb) => {
  const allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 
                       'video/mp4', 'video/quicktime',
                       'application/pdf'];
  if (allowedTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error('Invalid file type'), false);
  }
};

// Create uploads directory if not exists
const uploadDir = path.join(__dirname, '../uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploadDir);
  },
  filename: function (req, file, cb) {
    const ext = path.extname(file.originalname);
    const base = path.basename(file.originalname, ext);
    cb(null, `${base}-${Date.now()}${ext}`);
  }
});

const upload = multer({ 
  storage: storage,
  limits: { fileSize: 50 * 1024 * 1024 }, // 50MB
  fileFilter
});


/*
// Conflicting route removed to fix upload issues
router.post('/',
  authenticate,
  upload.single('content'), // Now properly configured
  courseController.createCourse
);
*/

router.post('/', upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ message: 'No file uploaded' });
  
  // Use correct URL format for serving files
  const fileUrl = `http://localhost:5000/uploads/${req.file.filename}`;
  res.status(200).json({ url: fileUrl });
});

module.exports = router;