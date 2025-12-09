const express = require('express');
const router = express.Router();
const { startSession, endLiveSession, sendLiveTask } = require('../controllers/liveSessionController');
const { requestJoinToken } = require('../controllers/roomController');
const auth = require('../middleware/auth');

router.post("/start", auth , startSession);
router.post('/end/:sessionId', auth, endLiveSession);
router.post('/join-token', auth, requestJoinToken);
router.post("/request-join", auth, requestJoinToken);
router.post('/task', auth, sendLiveTask);

module.exports = router;




