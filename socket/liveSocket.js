// socket/liveSocket.js
const LiveSession = require('../models/LiveSession');

module.exports = function liveSocket(io) {
  io.on('connection', (socket) => {
    const { sessionId, userId, role } = socket.roomAuth; // from token

    // attach simple metadata
    socket.userId = userId;
    socket.role = role;

    // Join the session room
    socket.join(sessionId);

    // Mark participant in DB (optional / light touch)
    LiveSession.findByIdAndUpdate(sessionId, { 
      $addToSet: { participants: { user: userId, joinedAt: new Date() } } 
    }).catch(e => console.error(e));

    io.to(sessionId).emit('participant-joined', { userId });

    // WebRTC signaling: forward signal to all others in room
    socket.on('signal', (payload) => {
      // payload should include target socket id or broadcast
      socket.to(sessionId).emit('signal', { from: userId, payload });
    });

    // Instructor-only events: kick, mute, sendTask
    socket.on('kick', ({ targetUserId }) => {
      if (socket.role !== 'instructor') return socket.emit('error', 'Not authorized');
      // broadcast kick to room
      io.to(sessionId).emit('kicked', { targetUserId });
      // optionally disconnect target sockets
      for (const [id, s] of io.of('/').sockets) {
        if (s.userId === targetUserId) {
          s.leave(sessionId);
          s.disconnect(true);
        }
      }
    });

    socket.on('sendTask', async (taskData) => {
      if (socket.role !== 'instructor') return socket.emit('error', 'Not authorized');
      // Save task to DB and emit
      // LiveTask.create(...) etc.
      io.to(sessionId).emit('newTask', { ...taskData, createdBy: userId, createdAt: Date.now() });
    });

    socket.on('disconnecting', () => {
      // optional cleanup
      io.to(sessionId).emit('participant-left', { userId });
    });

    socket.on('disconnect', () => {
      // final cleanup if needed
    });
  });
};
