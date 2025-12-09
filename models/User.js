  const mongoose = require("mongoose");

  const userSchema = new mongoose.Schema({
    // Basic info
    name: { type: String, required: true },
    email: { type: String, unique: true, required: true },
    password: { type: String, required: true },
    phoneNumber: { type: String }, // student phone

    // Parents info (for students)
    parentName: { type: String },
    parentPhone: { type: String },

    // Optional subscription code
    subscriptionCode: { type: String },

    // Profile photo
    photo: { type: String },   // uploaded file path
    avatar: { type: String, default: '' }, // optional avatar style

    // Status
    online: { type: Boolean, default: false },
    lastSeen: { type: Date, default: Date.now },

    // Roles
    role: {
      type: String,
      enum: ['student', 'assistant', 'admin'],
      default: 'student'
    },

    // Courses
    paidCourses: [{ type: mongoose.Schema.Types.ObjectId, ref: "Course" }],
    paidLessons: [{ type: mongoose.Schema.Types.ObjectId, ref: "Lesson" }],

    // Compiler access (only for practical enrolled students)
    hasCompilerAccess: { type: Boolean, default: false },

    // Metadata
    modelType: { type: String, default: 'User' }
  }, { timestamps: true });

  module.exports = mongoose.model("User", userSchema);
