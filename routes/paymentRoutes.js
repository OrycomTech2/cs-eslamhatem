// routes/paymentRoutes.js
const express = require('express');
const router = express.Router();
const upload = require('../middleware/upload'); // configure to accept screenshot images
const { createPaymentRequest, listUserRequests } = require('../controllers/paymentController');
const { authMiddleware } = require('../middleware/authenticate'); // user auth

router.get('/wallets', async (req,res)=>{ /* return hardcoded or DB wallet info */ });
router.post('/request', authMiddleware, upload.single('screenshot'), createPaymentRequest);
router.get('/user', authMiddleware, listUserRequests);

module.exports = router;
