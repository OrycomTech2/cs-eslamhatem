const Course = require('../models/Course');
const User = require('../models/User');
const Instructor = require('../models/Instructor');

// ✅ Define buyCourse as a variable
const buyCourse = async (req, res) => {
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
};

// ✅ Define enrollFreeCourse as a variable
const enrollFreeCourse = async (req, res) => {
  try {
    const courseId = req.params.id;
    const user = await User.findById(req.user.userId);

    if (!user) return res.status(404).json({ error: 'User not found' });

    if (user.paidCourses.includes(courseId)) {
      return res.status(400).json({ message: 'Already enrolled in this course' });
    }

    user.paidCourses.push(courseId);
    await user.save();

    res.json({ message: 'Enrolled successfully!' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Something went wrong' });
  }
};

const createCourse = async (req, res) => {
  try {
    const {
      title,
      description,
      instructor,
      pdf,
      duration,
      price,
      category,
      Level,
      quizzes,
      assignments
    } = req.body;

    const thumbnail = req.file ? req.file.filename : null;

    const newCourse = new Course({
      title,
      description,
      instructor,
      duration,
      pdf,
      price,
      category,
      Level,
      thumbnail,
      quizzes,
      assignments
    });

await newCourse.save();
res.status(201).json({ message: 'Course created successfully', course: newCourse });
  } catch (error) {
    console.error('Error creating course:', error);
    res.status(500).json({ message: 'Server error' });
  }
};

const getAllCourses = async (req, res) => {
  try {
    const courses = await Course.find()
      .populate('instructor', 'name email') // optionally populate instructor
      .select('-__v'); // remove __v field for cleaner output

    res.status(200).json({ success: true, courses });
  } catch (error) {
    console.error('Error fetching courses:', error);
    res.status(500).json({ success: false, message: 'Server Error' });
  }
};

const getCourse = async (req, res) => {
  try {
    const course = await Course.findById(req.params.id).populate('instructor', 'name email');
    if (!course) {
      return res.status(404).json({ error: 'Course not found' });
    }
    res.json(course);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};


// ✅ Correctly export all defined functions
module.exports = {
  createCourse,
  getAllCourses,
  getCourse,
  buyCourse,
  enrollFreeCourse
};
