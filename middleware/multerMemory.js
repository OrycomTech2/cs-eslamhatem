const multer = require('multer');
const path = require('path');

// Memory storage for handling files before uploading to R2
const memoryStorage = multer.memoryStorage();

// File filter for allowed file types
const fileFilter = (req, file, cb) => {
  const allowedTypes = [
    'image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/webp',
    'video/mp4', 'video/webm', 'video/ogg',
    'application/pdf',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
  ];
  
  if (allowedTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error('File type not allowed'), false);
  }
};

// Create multer instance with memory storage
const uploadMemory = multer({
  storage: memoryStorage,
  limits: { 
    fileSize: 10 * 1024 * 1024 * 1024, // 10 GB
    files: 10 // max number of files
  },
  fileFilter: fileFilter
});

module.exports = uploadMemory;