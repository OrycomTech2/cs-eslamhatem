const bcrypt = require("bcryptjs");
const User = require("../models/User");
const Course = require("../models/Course");
const Lesson = require("../models/Lesson");
const SubscriptionCode = require("../models/SubscriptionCode");
const LiveSession = require("../models/LiveSession");
/* ========================
   👤 Profile Management
======================== */
exports.getProfile = async (req, res) => {
  try {
    console.log("🟢 Incoming request to getProfile");

    // Debug the decoded user object
    console.log("Decoded user from JWT:", req.user);

    const userId = req.user.userId;
    if (!userId) {
      console.warn("⚠️ No userId found in JWT payload");
      return res.status(401).json({ message: "Unauthorized - Missing userId in token" });
    }

    console.log("Looking up user with ID:", userId);

    let user = await User.findById(userId).select("-password");
    if (!user) {
      console.warn("❌ No user found in DB for ID:", userId);
      return res.status(404).json({ message: "User not found" });
    }

    // Debug raw DB user
    console.log("✅ User found:", user);

    // Add full URL for photo
    const userObj = user.toObject();
    if (userObj.photo) {
      console.log("User has photo path:", userObj.photo);
      if (!userObj.photo.startsWith("http")) {
        userObj.photo = `${req.protocol}://${req.get("host")}/${userObj.photo}`;
        console.log("🔗 Full photo URL set to:", userObj.photo);
      }
    } else {
      console.log("ℹ️ User has no photo set");
    }

    res.json({ success: true, user: userObj });
  } catch (err) {
    console.error("🔥 Error fetching profile:", err);
    res.status(500).json({ error: "Server error", details: err.message });
  }
};




exports.updateProfilePhoto = async (req, res) => {
  try {
    const user = await User.findByIdAndUpdate(
      req.user.userId,
      { photo: req.file ? `uploads/profile/${req.file.filename}` : undefined },
      { new: true }
    ).select("-password");

    res.json({ message: "✅ Profile photo updated", user });
  } catch (err) {
    console.error("Error updating profile photo:", err);
    res.status(500).json({ error: "Server error" });
  }
};

exports.updateUserInfo = async (req, res) => {
  try {
    const { name, phoneNumber, parentName, parentPhone, subscriptionCode } = req.body;

    // Build update object dynamically (so we don’t overwrite with undefined values)
    const updateFields = {};
    if (name) updateFields.name = name;
    if (phoneNumber) updateFields.phoneNumber = phoneNumber;
    if (parentName) updateFields.parentName = parentName;
    if (parentPhone) updateFields.parentPhone = parentPhone;
    if (subscriptionCode) updateFields.subscriptionCode = subscriptionCode;

    const user = await User.findByIdAndUpdate(
      req.user.userId,
      { $set: updateFields },
      { new: true }
    ).select("-password");

    if (!user) return res.status(404).json({ message: "User not found" });

    res.json({ message: "✅ Info updated", user });
  } catch (err) {
    console.error("Error updating user info:", err);
    res.status(500).json({ error: "Server error", details: err.message });
  }
};


exports.changeUserPassword = async (req, res) => {
  try {
    console.log("🟢 Incoming change-password request");
    console.log("Body:", req.body);
    console.log("Decoded user from JWT:", req.user);

    const { oldPassword, newPassword } = req.body;
    if (!oldPassword || !newPassword) {
      return res.status(400).json({ message: "❌ Old and new passwords are required" });
    }

    const user = await User.findById(req.user.userId);
    if (!user) {
      console.log("❌ No user found with ID:", req.user.userId);
      return res.status(404).json({ message: "User not found" });
    }

    console.log("✅ Found user:", user.email);

    const isMatch = await bcrypt.compare(oldPassword, user.password);
    console.log("Password match:", isMatch);

    if (!isMatch) {
      return res.status(400).json({ message: "❌ Incorrect old password" });
    }

    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();

    console.log("✅ Password updated for:", user.email);
    res.json({ message: "✅ Password updated successfully" });
  } catch (err) {
    console.error("❌ Error changing password:", err);
    res.status(500).json({ error: "Server error", details: err.message });
  }
};

/* ========================
   📚 Courses
======================== */
exports.getMyCourses = async (req, res) => {
  try {
    console.log("User ID from token:", req.user.userId); // 👈 check if token works
    const user = await User.findById(req.user.userId).populate("paidCourses");
    if (!user) {
      console.log("No user found");
      return res.status(404).json({ error: "User not found" });
    }
    console.log("Paid courses:", user.paidCourses);
    res.json(user.paidCourses);
  } catch (err) {
    console.error("Error fetching my courses:", err);
    res.status(500).json({ error: "Server error" });
  }
};

exports.getMyLessons = async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).populate("paidLessons");
    res.json(user.paidLessons);
  } catch (err) {
    console.error("Error fetching my lessons:", err);
    res.status(500).json({ error: "Server error" });
  }
};
exports.getCourseLessons = async (req, res) => {
  try {
    const { courseId } = req.params;
    console.log("Received courseId:", courseId);

    const lessons = await Lesson.find({ course: courseId });
    console.log("Found lessons:", lessons);

    res.json(lessons);
  } catch (err) {
    console.error("Error fetching course lessons:", err);
    res.status(500).json({ error: "Server error" });
  }
};


exports.enrollUserInCourse = async (req, res) => {
  try {
    const { courseId } = req.params;
    const user = await User.findById(req.user.userId);
    const course = await Course.findById(courseId);

    if (!course) return res.status(404).json({ message: "Course not found" });

    if (user.paidCourses.includes(courseId)) {
      return res.status(400).json({ message: "Already enrolled" });
    }

    user.paidCourses.push(courseId);

    if (course.type === "Practical") {
      user.hasCompilerAccess = true;
    }

    await user.save();
    res.json({ message: "✅ Enrolled successfully", courseId });
  } catch (err) {
    console.error("Error enrolling in course:", err);
    res.status(500).json({ error: "Server error" });
  }
};

exports.buyCourse = async (req, res) => {
  try {
    const { userId, courseId } = req.params;
    const user = await User.findById(userId);
    const course = await Course.findById(courseId);

    if (!user || !course) {
      return res.status(404).json({ message: "User or course not found" });
    }

    if (user.paidCourses.includes(course._id)) {
      return res.status(400).json({ message: "Course already purchased" });
    }

    user.paidCourses.push(course._id);

    if (course.type === "Practical") {
      user.hasCompilerAccess = true;
    }

    await user.save();
    res.json({ message: "✅ Course purchased successfully", courseId: course._id });
  } catch (err) {
    console.error("Purchase error:", err);
    res.status(500).json({ message: "Server error" });
  }
};

/* ========================
   🖼 Profile Photo Helper
======================== */
exports.findUserById = async (id) => {
  return await User.findById(id).select("photo");
};

/* ========================
   📊 Dashboard
======================== */
exports.getDashboardData = async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).populate("paidCourses");
    res.json({
      name: user.name,
      email: user.email,
      role: user.role,
      courses: user.paidCourses,
      hasCompilerAccess: user.hasCompilerAccess
    });
  } catch (err) {
    console.error("Error fetching dashboard:", err);
    res.status(500).json({ error: "Server error" });
  }
};
exports.getCourseById = async (req, res) => {
  try {
    const { id } = req.params;

    const course = await Course.findById(id)
      .populate("instructor", "name email")   // show instructor info
      .populate("assistants", "name email")   // show assistants
      .populate("lessons", "title type")      // only basic info
      .populate("assignments", "title dueDate")
      .populate("liveSessions", "title date link");

    if (!course) {
      return res.status(404).json({ success: false, error: "Course not found" });
    }

    res.json({ success: true, data: course });
  } catch (err) {
    console.error("Get course by ID error:", err);
    res.status(500).json({ success: false, error: "Server error" });
  }
};
/* ========================
   🎥 Live Sessions
======================== */
exports.getAvailableLiveSessions = async (req, res) => {
  try {
    const userId = req.user.userId;
    const user = await User.findById(userId)
      .populate("paidCourses", "title _id type")

    if (!user) return res.status(404).json({ message: "User not found" });

    // Get all user's courses (both paid and enrolled)
    const userCourses = [...user.paidCourses];
    const userCourseIds = userCourses.map(course => course._id.toString());

    // Get active rooms from the server
    const activeRooms = req.app.get("activeRooms") || {};
    
    // Get scheduled live sessions from database
    const currentTime = new Date();
    const upcomingTime = new Date(currentTime.getTime() + 2 * 60 * 60 * 1000); // Next 2 hours
    
    const scheduledSessions = await LiveSession.find({
      course: { $in: userCourseIds },
      scheduledAt: { 
        $gte: currentTime,
        $lte: upcomingTime
      },
      status: 'scheduled'
    })
    .populate('course', 'title instructor')
    .populate('instructor', 'name')
    .sort({ scheduledAt: 1 });

    const availableSessions = [];

    // 1. Add currently active rooms
    for (const [roomId, roomData] of Object.entries(activeRooms)) {
      // Check if user is enrolled in this course
      const isEnrolled = userCourseIds.includes(roomData.courseId);
      
      if (isEnrolled) {
        const course = userCourses.find(c => c._id.toString() === roomData.courseId);
        
        availableSessions.push({
          roomId,
          courseId: roomData.courseId,
          courseTitle: course?.title || "Unknown Course",
          isLive: true,
          type: 'active'
        });
      }
    }

    // 2. Add upcoming scheduled sessions
    for (const session of scheduledSessions) {
      // Check if this session is not already active
      const isAlreadyActive = Object.values(activeRooms).some(
        room => room.courseId === session.course._id.toString()
      );
      
      if (!isAlreadyActive) {
        availableSessions.push({
          roomId: `scheduled_${session._id}`,
          courseId: session.course._id.toString(),
          courseTitle: session.course.title,
          scheduledAt: session.scheduledAt,
          duration: session.duration,
          isLive: false,
          type: 'scheduled'
        });
      }
    }

    res.status(200).json({ 
      success: true,
      data: availableSessions 
    });
  } catch (err) {
    console.error("Error fetching live sessions:", err);
    res.status(500).json({ 
      success: false,
      message: "Error fetching live sessions", 
      error: err.message 
    });
  }
};



// ============================
// Get single lesson details
// ============================
exports.getLessonById = async (req, res) => {
  try {
    const lesson = await Lesson.findById(req.params.id).select(
      "title description type price material video thumbnail course createdAt"
    ).populate("course", "title _id"); // populate course basic info

    if (!lesson) {
      return res.status(404).json({ success: false, message: "Lesson not found" });
    }

    res.json({ success: true, data: lesson });
  } catch (err) {
    console.error("❌ Error fetching lesson:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
};

// ============================
// Get all lessons for a course
// ============================
exports.getLessonsByCourse = async (req, res) => {
  try {
    console.log("📥 Request received for course lessons");
    console.log("➡️ Params:", req.params);
    console.log("➡️ User from token:", req.user);

    const lessons = await Lesson.find({ course: req.params.courseId }).select(
      "title description type thumbnail "
    );

    console.log("✅ Lessons found:", lessons.length);

    // Debug each lesson (optional)
    lessons.forEach((lesson, index) => {
      console.log(`   Lesson ${index + 1}:`, lesson.title, "-", lesson._id);
    });

    res.json({ success: true, lessons }); // 🔑 return lessons inside 'lessons'
  } catch (err) {
    console.error("❌ Error fetching lessons:", err);
    debugger; // <-- put breakpoint here if running in Node inspector
    res.status(500).json({ success: false, message: "Server error" });
  }
};


// ============================
// Stream lesson video
// ============================
exports.streamLessonVideo = async (req, res) => {
  try {
    const lesson = await Lesson.findById(req.params.id).select("video");
    if (!lesson || !lesson.video) {
      return res.status(404).json({ success: false, message: "Video not found" });
    }

    // Path where video is stored
    const videoPath = path.join(__dirname, "../uploads/videos", lesson.video);

    // Check if file exists
    if (!fs.existsSync(videoPath)) {
      return res.status(404).json({ success: false, message: "Video file missing" });
    }

    const stat = fs.statSync(videoPath);
    const fileSize = stat.size;
    const range = req.headers.range;

    if (range) {
      // Handle partial content (streaming)
      const parts = range.replace(/bytes=/, "").split("-");
      const start = parseInt(parts[0], 10);
      const end = parts[1] ? parseInt(parts[1], 10) : fileSize - 1;
      const chunkSize = end - start + 1;

      const file = fs.createReadStream(videoPath, { start, end });
      const head = {
        "Content-Range": `bytes ${start}-${end}/${fileSize}`,
        "Accept-Ranges": "bytes",
        "Content-Length": chunkSize,
        "Content-Type": "video/mp4", // adjust if other formats
      };

      res.writeHead(206, head);
      file.pipe(res);
    } else {
      // Send whole file if no range
      const head = {
        "Content-Length": fileSize,
        "Content-Type": "video/mp4",
      };
      res.writeHead(200, head);
      fs.createReadStream(videoPath).pipe(res);
    }
  } catch (err) {
    console.error("❌ Video stream error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
};


// User redeems subscription code
exports.redeemSubscriptionCode = async (req, res) => {
  try {
    const { code } = req.body;
    const userId = req.user.userId;

    const subscriptionCode = await SubscriptionCode.findOne({ code }).populate("courses");

    if (!subscriptionCode) {
      return res.status(404).json({ success: false, message: "Invalid code" });
    }
    if (subscriptionCode.isUsed) {
      return res.status(400).json({ success: false, message: "Code already used" });
    }

    // Enroll user in all courses of the package
    await User.findByIdAndUpdate(userId, {
      $addToSet: { paidCourses: { $each: subscriptionCode.courses.map(c => c._id) } }
    });

    // Mark code as used
    subscriptionCode.isUsed = true;
    subscriptionCode.usedBy = userId;
    subscriptionCode.usedAt = new Date();
    await subscriptionCode.save();

    res.json({ success: true, message: "Subscription code redeemed successfully", courses: subscriptionCode.courses });
  } catch (err) {
    console.error("❌ Error redeeming subscription code:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
};