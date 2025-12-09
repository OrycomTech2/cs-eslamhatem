const PaymentRequest = require('../models/PaymentRequest');
const Course = require('../models/Course');
const User = require('../models/User');
const Admin = require('../models/Admin');
const Lesson = require('../models/Lesson');

// Create new payment request (student/instructor)
// Create new payment request
/* ========================
   🔹 Create Payment Request
======================== */
exports.createPaymentRequest = async (req, res) => {
  try {
    const userId = req.user.userId;
    const { courseId, lessonId, amount, method, walletId, PhoneNumber } = req.body;

    if ((!courseId && !lessonId) || !amount || !method || !walletId || !PhoneNumber) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    // check course OR lesson
    if (courseId) {
      const existingCourse = await Course.findById(courseId);
      if (!existingCourse) return res.status(404).json({ error: "Course not found" });
    }

    if (lessonId) {
      const existingLesson = await Lesson.findById(lessonId);
      if (!existingLesson) return res.status(404).json({ error: "Lesson not found" });
    }

    const screenshot = req.file ? `/uploads/profile/${req.file.filename}` : null;

    const paymentRequest = await PaymentRequest.create({
      user: userId,
      course: courseId || null,
      lesson: lessonId || null,
      amount,
      PhoneNumber,
      method,
      walletId,
      screenshotUrl: screenshot,
    });

    res.status(201).json({ success: true, data: paymentRequest });
  } catch (err) {
    console.error("Create payment request error:", err);
    res.status(500).json({ error: "Server error creating payment request" });
  }
};

/* ========================
   🔹 Get My Payment Requests
======================== */
exports.getMyRequests = async (req, res) => {
  try {
    const userId = req.user.userId;
    const requests = await PaymentRequest.find({ user: userId })
      .populate("course", "title thumbnail price")
      .populate("lesson", "title price")
      .sort({ createdAt: -1 });
    res.json({ success: true, data: requests });
  } catch (err) {
    console.error("Get my requests error:", err);
    res.status(500).json({ error: "Server error" });
  }
};

/* ========================
   🔹 Admin: Get All Requests
======================== */
exports.getAllRequests = async (req, res) => {
  try {
    const requests = await PaymentRequest.find()
      .populate("user", "name email")
      .populate("course", "title")
      .populate("lesson", "title")
      .populate("processedBy", "username")
      .sort({ createdAt: -1 });
    res.json({ success: true, data: requests });
  } catch (err) {
    console.error("Get all requests error:", err);
    res.status(500).json({ error: "Server error" });
  }
};

/* ========================
   🔹 Admin: Approve Request
======================== */
// Approve
exports.approveRequest = async (req, res) => {
  try {
    const request = await PaymentRequest.findById(req.params.id);
    if (!request) {
      return res.status(404).json({ success: false, message: "Request not found" });
    }

    // Update request status
    request.status = "approved";
    await request.save();

    // Add course or lesson to user model
    const user = await User.findById(request.user);
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    if (request.course) {
      // Only push if not already enrolled
      if (!user.paidCourses.includes(request.course)) {
        user.paidCourses.push(request.course);
      }
    }

    if (request.lesson) {
      if (!user.paidLessons.includes(request.lesson)) {
        user.paidLessons.push(request.lesson);
      }
    }

    await user.save();

    res.json({
      success: true,
      message: "Payment request approved and access granted",
      request,
      user
    });
  } catch (err) {
    console.error("Approve error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
};


// Reject
exports.rejectRequest = async (req, res) => {
  try {
    const { reason } = req.body;
    const request = await PaymentRequest.findById(req.params.id);
    if (!request) return res.status(404).json({ success: false, message: "Request not found" });

    request.status = "rejected";
    request.rejectionReason = reason || "No reason provided";
    await request.save();

    res.json({ success: true, message: "Payment request rejected", request });
  } catch (err) {
    console.error("Reject error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
};






// controllers/paymentRequestController.js
exports.getUserRequests = async (req, res) => {
  try {
    const { userId } = req.params;
    const requests = await PaymentRequest.find({ user: userId }).select('course status');
    
    res.json({ success: true, requests });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
};
exports.getUserLessonRequests = async (req, res) => {
  try {
    const { userId } = req.params;

    // Only get lesson payment requests (exclude course-only payments)
    const requests = await PaymentRequest.find({ user: userId, lesson: { $ne: null } })
      .select('lesson status')
      
    res.json({ success: true, requests });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error" });
  }
};
