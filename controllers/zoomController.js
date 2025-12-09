const zoomService = require('../services/zoomService');

const zoomController = {
  createRoom: async (req, res) => {
    try {
      const { courseId, instructorId } = req.body;
      const room = await zoomService.createRoom({ courseId, instructorId });
      res.json({ success: true, room });
    } catch (error) {
      res.status(500).json({ success: false, error: error.message });
    }
  },

  joinRoom: async (req, res) => {
    try {
      const { roomId, userId } = req.body;
      const room = await zoomService.joinRoom({ roomId, userId });
      res.json({ success: true, room });
    } catch (error) {
      res.status(500).json({ success: false, error: error.message });
    }
  },

  getRoom: async (req, res) => {
    try {
      const room = await zoomService.getRoom(req.params.roomId);
      res.json({ success: true, room });
    } catch (error) {
      res.status(500).json({ success: false, error: error.message });
    }
  },

  startRecording: async (req, res) => {
    res.json({ success: true, message: 'Recording started' });
  },

  startScreenShare: async (req, res) => {
    res.json({ success: true, message: 'Screen sharing started' });
  },

  endCall: async (req, res) => {
    try {
      const result = await zoomService.endCall(req.body);
      res.json({ success: true, result });
    } catch (error) {
      res.status(500).json({ success: false, error: error.message });
    }
  }
};

module.exports = zoomController;
