const mongoose = require('mongoose');

const liveTaskSchema = new mongoose.Schema({
    session: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'LiveSession',
        required: true
    },
    question: { type: String, required: true },
    createdAt: { type: Date, default: Date.now },
    answers: [{
        student: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
        answerText: String,
        submittedAt: { type: Date, default: Date.now }
    }]
});

module.exports = mongoose.model('LiveTask', liveTaskSchema);
