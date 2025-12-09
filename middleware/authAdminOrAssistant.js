// middleware/authAdminOrAssistant.js
const jwt = require('jsonwebtoken');
const Admin = require('../models/Admin');
const Assistant = require('../models/Assistant');

const authenticateAdminOrAssistant = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ message: 'Unauthorized: No token provided' });
    }

    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // Try Admin first
    let user = await Admin.findById(decoded.userId);
    if (user && user.role === "admin") {
      req.user = { userId: user._id, role: "admin", email: user.email };
      return next();
    }

    // Try Assistant if not admin
    user = await Assistant.findById(decoded.userId);
    if (user) {
      req.user = { userId: user._id, role: "assistant" };
      return next();
    }

    return res.status(401).json({ message: "Unauthorized: Not admin or assistant" });
  } catch (err) {
    console.error("❌ Auth failed:", err.message);
    return res.status(401).json({ message: "Unauthorized: Token verification failed" });
  }
};

module.exports = authenticateAdminOrAssistant;
