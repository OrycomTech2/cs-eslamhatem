const jwt = require("jsonwebtoken");
const Admin = require("../models/Admin");

module.exports = async function (req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ message: "No token" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const admin = await Admin.findById(decoded.id);
    if (!admin) return res.status(401).json({ message: "Unauthorized" });

    req.admin = admin;
    next();
  } catch {
    return res.status(401).json({ message: "Invalid token" });
  }
};
