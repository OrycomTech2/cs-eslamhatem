const express = require('express');
const { v4: uuidV4 } = require('uuid');
const router = express.Router();

// Create a new host room (for instructors)
router.get('/create-room', (req, res) => {
  const roomId = uuidV4();
  res.json({ roomId });
});

module.exports = router;
