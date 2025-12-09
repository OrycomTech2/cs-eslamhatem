const jwt = require('jsonwebtoken');
const User = require('../models/Assistant'); // still Assistant model

const authenticateAssistant = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ message: 'Unauthorized: No token provided' });
    }

    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    console.log("Decoded token:", decoded);

    // ✅ just check if assistant exists, no role validation
    const assistant = await User.findById(decoded.userId);
    if (!assistant) {
      return res.status(401).json({ message: 'Unauthorized: Invalid token' });
    }

    req.user = { userId: assistant._id }; // no role attached
    next();
  } catch (err) {
    console.error("Assistant auth error:", err);
    return res.status(401).json({ message: 'Unauthorized: Token verification failed' });
  }
};

module.exports = authenticateAssistant;
