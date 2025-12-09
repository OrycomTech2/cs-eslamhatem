    const User = require('../models/User');
    const Course = require('../models/Course');
    const Instructor = require('../models/Instructor');
    
    
    // GET /api/instructors
    exports.getInstructor = async (req, res) => {
  try {
    const instructors = await Instructor.find();
    res.json(instructors);
  } catch (err) {
    res.status(500).json({ message: 'Failed to fetch instructors' });
  }
};

    // POST /api/instructors
exports.addInstructor = async (req, res) => {
  console.log('📥 Add Instructor called');
  console.log('📸 File:', req.file);
  console.log('📦 Body:', req.body);

  try {
    const { name, email, password } = req.body;
    const photo = req.file ? req.file.filename : '';

    if (!name || !email || !password) {
      return res.status(400).json({ message: 'Missing fields' });
    }

    const existing = await Instructor.findOne({ email });
    if (existing) return res.status(400).json({ message: 'Instructor already exists' });

    const newInstructor = new Instructor({
      name,
      email,
      password,
      photo,
    });

    await newInstructor.save();
    res.status(201).json({ message: 'Instructor created successfully' });
  } catch (err) {
    console.error('❌ Error in addInstructor:', err);
    res.status(500).json({ message: 'Failed to create instructor' });
  }
};





    // PUT /api/instructors/:id
exports.updateInstructor = async (req, res) => {
  try {
    const { name, email } = req.body;
    const photo = req.file?.filename;

    const updateData = { name, email };
    if (photo) updateData.photo = photo;

    const updated = await Instructor.findByIdAndUpdate(req.params.id, updateData, { new: true });
    if (!updated) return res.status(404).json({ message: 'Instructor not found' });

    res.json({ message: 'Instructor updated', updated });
  } catch (err) {
    console.error('❌ Error in updateInstructor:', err);
    res.status(500).json({ message: 'Update failed' });
  }
};




    // GET /api/instructors/:id/courses
    exports.getInstructorCourses = async (req, res) => {
    try {
        const courses = await Course.find({ instructor: req.params.id });
        res.json(courses);
    } catch (err) {
        res.status(500).json({ message: 'Error fetching courses' });
    }
    };


    // ✅ Get Instructor Profile
exports.getInstructorProfile = async (req, res) => {
  try {
    const instructor = await Instructor.findById(req.user.userId).select("-password");
    if (!instructor) return res.status(404).json({ message: "Instructor not found" });
    res.json(instructor);
  } catch (err) {
    res.status(500).json({ message: "Error fetching profile" });
  }
};

// ✅ Update Instructor Info
exports.updateInstructorInfo = async (req, res) => {
  try {
    const updateData = req.body;
    const instructor = await Instructor.findByIdAndUpdate(
      req.user.userId,
      updateData,
      { new: true }
    ).select("-password");

    if (!instructor) return res.status(404).json({ message: "Instructor not found" });

    res.json({ message: "Profile updated", instructor });
  } catch (err) {
    res.status(500).json({ message: "Error updating profile" });
  }
};

// ✅ Update Instructor Photo
exports.updateInstructorPhoto = async (req, res) => {
  try {
    const photo = req.file ? req.file.filename : null;
    if (!photo) return res.status(400).json({ message: "No photo uploaded" });

    const instructor = await Instructor.findById(req.user.userId);
    if (!instructor) return res.status(404).json({ message: "Instructor not found" });

    instructor.photo = photo;
    await instructor.save();

    res.json({ message: "Profile photo updated", photo });
  } catch (err) {
    res.status(500).json({ message: "Error updating photo" });
  }
};

// ✅ Change Password
exports.changeInstructorPassword = async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body;
    const instructor = await Instructor.findById(req.user.userId);

    if (!instructor) return res.status(404).json({ message: "Instructor not found" });

    const isMatch = await instructor.comparePassword(oldPassword);
    if (!isMatch) return res.status(400).json({ message: "Incorrect old password" });

    instructor.password = await bcrypt.hash(newPassword, 12);
    await instructor.save();

    res.json({ message: "Password updated successfully" });
  } catch (err) {
    res.status(500).json({ message: "Error changing password" });
  }
};