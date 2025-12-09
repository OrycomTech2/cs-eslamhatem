const jwt = require('jsonwebtoken');
const Admin = require('../models/Admin'); // ✅ use Admin model

const authenticateAdmin = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ message: 'Unauthorized: No token provided' });
    }

    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // ✅ find admin in Admin collection
    const admin = await Admin.findById(decoded.userId);
    if (!admin || admin.role !== 'admin') {
      return res.status(401).json({ message: 'Unauthorized: Invalid token' });
    }

    // attach admin info to request
    req.user = { userId: admin._id, role: admin.role, email: admin.email };
    next();
  } catch (err) {
    console.error("❌ Admin authentication failed:", err.message);
    return res.status(401).json({ message: 'Unauthorized: Token verification failed' });
  }
};

module.exports = authenticateAdmin;
