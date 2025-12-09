// middleware/authAnyRole.js
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const Instructor = require('../models/Instructor');
const Admin = require('../models/Admin'); // create if you have an Admin model

module.exports = async function authAnyRole(req, res, next) {
  try {
    const hdr = req.headers.authorization || '';
    const token = hdr.startsWith('Bearer ') ? hdr.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'No token provided' });

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const id = decoded.userId || decoded.adminId || decoded.instructorId || decoded._id || decoded.id;

    // Try to find the principal in all three collections:
    let principal = await User.findById(id).select('_id name email photo');
    if (principal) {
      req.principal = { role: 'user', id: principal._id, name: principal.name, photo: principal.photo || null };
      return next();
    }

    principal = await Instructor.findById(id).select('_id name email photo');
    if (principal) {
      req.principal = { role: 'instructor', id: principal._id, name: principal.name, photo: principal.photo || null };
      return next();
    }

    principal = await Admin.findById(id).select('_id name email photo');
    if (principal) {
      req.principal = { role: 'admin', id: principal._id, name: principal.name, photo: principal.photo || null };
      return next();
    }

    return res.status(401).json({ error: 'Account not found for token' });
  } catch (err) {
    console.error('authAnyRole error:', err);
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
};
