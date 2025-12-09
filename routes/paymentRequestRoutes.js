const express = require('express');
const router = express.Router();
const authenticate = require('../middleware/authenticate');
const authenticateAdmin = require('../middleware/authenticateAdmin');
const upload = require('../middleware/upload'); // multer configured to store screenshots
const controller = require('../controllers/paymentRequestController');

router.post(
  "/submit",
  authenticate,
  upload.single("screenshot"),
  controller.createPaymentRequest
);

// 🔹 User: View own requests
router.get("/my-requests", authenticate, controller.getMyRequests);

// 🔹 Admin: View all requests
router.get("/all", authenticateAdmin, controller.getAllRequests);

// 🔹 Admin: Approve / Reject requests
router.patch("/approve/:id", authenticateAdmin, controller.approveRequest);
router.patch("/reject/:id", authenticateAdmin, controller.rejectRequest);

// (optional) Admin: View specific user’s requests
router.get("/user/:userId", authenticate, controller.getUserRequests);
router.get("/user/:userId/lessons", authenticate, controller.getUserLessonRequests);

module.exports = router;
