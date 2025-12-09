// routes/helpRoutes.js
const express = require("express");
const router = express.Router();
const { submitRequest, getAllRequests, updateStatus } = require("../controllers/helpController");
const authenticate = require("../middleware/authenticate");
const upload = require("../middleware/upload");
const authenticateAdmin = require("../middleware/authenticateAdmin");

// Student/Instructor submit request
router.post("/submit", authenticate, upload.single("attachment"), submitRequest);

// Admin view all requests
router.get("/all", authenticateAdmin, getAllRequests);

// Admin update request status
router.put("/status/:id", authenticateAdmin, updateStatus);

module.exports = router;
