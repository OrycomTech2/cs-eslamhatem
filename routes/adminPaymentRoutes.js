// routes/adminPaymentRoutes.js
const express = require('express');
const router = express.Router();
const { authenticateAdmin } = require('../middleware/authenticateAdmin');
const { listPending, approve, reject } = require('../controllers/adminPaymentController');

router.get('/payments/pending', authenticateAdmin, listPending);
router.put('/payments/:id/approve', authenticateAdmin, approve);
router.put('/payments/:id/reject', authenticateAdmin, reject);
module.exports = router;
