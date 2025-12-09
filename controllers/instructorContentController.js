const Content = require('../models/Content');
const Instructor = require('../models/Instructor');
const fs = require('fs');

const uploadInstructorContent = async (req, res) => {
  try {
    const { instructorId, title, contentType, courseId } = req.body;

    if (!req.file) return res.status(400).json({ message: 'No file uploaded' });

    const content = new Content({
      instructor: instructorId,
      title: title || req.file.originalname,
      fileType: req.file.mimetype,
      filePath: req.file.path,
      contentType,
      course: courseId || null
    });

    await content.save();

    res.status(201).json({ message: 'Content uploaded successfully', content });
  } catch (error) {
    console.error('Upload error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
};

const getContentByInstructor = async (req, res) => {
  try {
    const instructorId = req.params.id;
    const content = await Content.find({ instructor: instructorId }).populate('course');
    res.status(200).json(content);
  } catch (err) {
    res.status(500).json({ message: 'Failed to fetch content' });
  }
};

module.exports = {
  uploadInstructorContent,
  getContentByInstructor
};
