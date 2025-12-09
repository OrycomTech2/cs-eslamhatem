const Content = require('../models/Content'); // Lessons model
const User = require('../models/User');

exports.getMyAssignments = async (req, res) => {
    try {
        // Get student with enrolled courses
        const user = await User.findById(req.user.id).populate('paidCourses');
        const courseIds = user.paidCourses.map(course => course._id);

        // Find assignments from lessons in enrolled courses
        const lessons = await Content.find({ course: { $in: courseIds } }, 'assignments title course')
            .populate('course', 'title');

        // Flatten assignments with lesson info
        const assignments = [];
        lessons.forEach(lesson => {
            lesson.assignments.forEach(a => {
                assignments.push({
                    assignmentId: a._id,
                    question: a.question,
                    dueDate: a.dueDate,
                    lessonTitle: lesson.title,
                    courseTitle: lesson.course.title
                });
            });
        });

        res.json(assignments);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};

exports.submitAssignment = async (req, res) => {
    try {
        const { assignmentId } = req.params;
        const file = req.file ? req.file.filename : null;
        const answerText = req.body.answer || '';

        // Save submission record (can use separate model if needed)
        const submission = {
            student: req.user.id,
            assignment: assignmentId,
            answerText,
            file
        };

        // Save to DB (you could have a `Submission` model)
        // For demo, just return
        res.json({ message: 'Assignment submitted successfully!', submission });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};
