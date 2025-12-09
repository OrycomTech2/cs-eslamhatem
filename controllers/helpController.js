// controllers/helpController.js
const HelpRequest = require("../models/HelpRequest");

// Submit help request (students/instructors)
exports.submitRequest = async (req, res) => {
  try {
    const { subject, message, role } = req.body;
    const attachment = req.file ? req.file.filename : null;

    const request = new HelpRequest({
      sender: req.user.id,
      role,
      subject,
      message,
      attachment
    });

    await request.save();
    res.status(201).json({ message: "Help request submitted successfully", request });
  } catch (err) {
    res.status(500).json({ error: "Failed to submit request" });
  }
};

// Admin: View all help requests
exports.getAllRequests = async (req, res) => {
  try {
    const requests = await HelpRequest.find().populate("sender", "name email");
    res.json(requests);
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch requests" });
  }
};

// Admin: Update request status
exports.updateStatus = async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;

    const request = await HelpRequest.findByIdAndUpdate(id, { status }, { new: true });
    res.json(request);
  } catch (err) {
    res.status(500).json({ error: "Failed to update status" });
  }
};
