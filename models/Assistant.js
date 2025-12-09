    // models/Assistant.js
    const mongoose = require("mongoose");
    const bcrypt = require("bcryptjs");

    const assistantSchema = new mongoose.Schema({
    name: { type: String, required: true, trim: true },
    email: { type: String, required: true, unique: true, lowercase: true },
    password: { type: String, required: true },
    photo: { type: String },
    phoneNumber: { type: String },
    assignedCourses: [{ type: mongoose.Schema.Types.ObjectId, ref: "Course" }],
    role: { type: String, default: "assistant" },
    }, { timestamps: true });

    // hash password
    assistantSchema.pre("save", async function (next) {
    if (!this.isModified("password")) return next();
    this.password = await bcrypt.hash(this.password, 10);
    next();
    });

    // compare password
    assistantSchema.methods.matchPassword = async function (enteredPassword) {
    return await bcrypt.compare(enteredPassword, this.password);
    };

    module.exports = mongoose.model("Assistant", assistantSchema);

