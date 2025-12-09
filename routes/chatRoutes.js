// routes/chatRoutes.js
const router = require('express').Router();
const authAnyRole = require('../middleware/authAnyRole');
const chat = require('../controllers/chatController');

router.use(authAnyRole);

// general room (auto-create once)
router.get('/general', chat.ensureGeneralRoom);

// list my rooms
router.get('/rooms', chat.getMyRooms);

// ensure DM room (create if not exists)
router.post('/rooms/dm', chat.ensureDMRoom);

// messages
router.get('/rooms/:roomId/messages', chat.getMessages);
router.post('/rooms/:roomId/messages', chat.postMessage);

module.exports = router;
