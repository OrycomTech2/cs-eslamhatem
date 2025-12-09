const mongoose = require('mongoose');
const bcrypt = require('bcrypt');


const instructorSchema = new mongoose.Schema({
name: String,
email: { type: String, required: true, unique: true },
password: String,
  photo: String,
  avatar: { type: String, default: '' },
  online: { type: Boolean, default: false },
  lastSeen: { type: Date },
  coursesTeaching: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Course' }],
  qualifications: { type: String },

  bio: String,
  role: { type: String, enum: ["instructor"], default: "instructor" },
  specialization: String,
  socialLinks: {
    linkedin: String,
    twitter: String,
    youtube: String,
  },
  contents: [
    {
      title: String,
      type: {
        type: String,
        enum: ['video', 'pdf', 'quiz', 'assignment'],
      },
      url: String,
      createdAt: {
        type: Date,
        default: Date.now,
      },
    },
  ],
}, { timestamps: true });



// Hash password before saving
instructorSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

instructorSchema.methods.comparePassword = function (candidate) {
  return bcrypt.compare(candidate, this.password);
};

module.exports = mongoose.model('Instructor', instructorSchema);
