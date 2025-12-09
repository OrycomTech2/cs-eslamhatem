// server-mediasoup.js
const mediasoup = require('mediasoup');
const { v4: uuidv4 } = require('uuid');

let worker = null;
const routers = {};          // routers[roomId] = mediasoup Router
const transports = {};       // transports[transportId] = { transport, roomId, userId }
const producers = {};        // producers[producerId] = { producer, roomId, userId }
const consumers = {};        // consumers[consumerId] = { consumer, roomId, userId }

async function createWorker() {
  worker = await mediasoup.createWorker({
    rtcMinPort: 20000,
    rtcMaxPort: 20200,
    logLevel: 'warn',
    logTags: ['info', 'ice', 'dtls', 'rtp', 'srtp', 'rtcp'],
  });

  worker.on('died', () => {
    console.error('mediasoup worker died — exiting in 2s ...');
    setTimeout(() => process.exit(1), 2000);
  });

  console.log('✅ mediasoup worker created');
}

async function ensureRouter(roomId) {
  if (routers[roomId]) return routers[roomId];

  // Use a simple single-media-codec router config (you can expand later)
  const mediaCodecs = [
    {
      kind: 'audio',
      mimeType: 'audio/opus',
      clockRate: 48000,
      channels: 2
    },
    {
      kind: 'video',
      mimeType: 'video/VP8',
      clockRate: 90000,
      parameters: {}
    }
  ];

  const router = await worker.createRouter({ mediaCodecs });
  routers[roomId] = router;
  console.log(`🧭 Created router for room ${roomId}`);
  return router;
}

function setupSocketSignaling(io) {
  io.on('connection', (socket) => {
    // We reuse your existing io connection; this will add mediasoup handlers.
    console.log('Socket connected for mediasoup:', socket.id);

    // Create a mediasoup transport (for either producing or consuming)
    socket.on('mediasoup-create-transport', async ({ roomId }, callback) => {
      try {
        const router = await ensureRouter(roomId);
        const transport = await router.createWebRtcTransport({
          listenIps: [{ ip: '0.0.0.0', announcedIp: process.env.PUBLIC_IP || null }], // announcedIp for NAT
          enableUdp: true,
          enableTcp: true,
          preferUdp: true,
          initialAvailableOutgoingBitrate: 1000000,
        });

        transports[transport.id] = { transport, roomId, socketId: socket.id };
        callback({
          ok: true,
          params: {
            id: transport.id,
            iceParameters: transport.iceParameters,
            iceCandidates: transport.iceCandidates,
            dtlsParameters: transport.dtlsParameters
          }
        });
      } catch (err) {
        console.error('create-transport error', err);
        callback({ ok: false, error: err.message });
      }
    });

    // Connect transport (client sets DTLS params)
    socket.on('mediasoup-connect-transport', async ({ transportId, dtlsParameters }, callback) => {
      try {
        const t = transports[transportId];
        if (!t) throw new Error('transport not found');
        await t.transport.connect({ dtlsParameters });
        callback({ ok: true });
      } catch (err) {
        console.error('connect-transport error', err);
        callback({ ok: false, error: err.message });
      }
    });

    // Produce (teacher publishes audio/video)
    socket.on('mediasoup-produce', async ({ transportId, kind, rtpParameters, appData }, callback) => {
      try {
        const t = transports[transportId];
        if (!t) throw new Error('transport not found');

        const producer = await t.transport.produce({ kind, rtpParameters, appData });
        producers[producer.id] = { producer, roomId: t.roomId, socketId: socket.id, kind };

        // Broadcast to room that a new producer exists (students can then request to consume)
        socket.to(t.roomId).emit('new-producer', { producerId: producer.id, kind });

        callback({ ok: true, id: producer.id });
      } catch (err) {
        console.error('produce error', err);
        callback({ ok: false, error: err.message });
      }
    });

    // Consumer creation for subscribers
    socket.on('mediasoup-consume', async ({ roomId, producerId, rtpCapabilities }, callback) => {
      try {
        const router = await ensureRouter(roomId);
        const canConsume = router.canConsume({
          producerId,
          rtpCapabilities
        });
        if (!canConsume) return callback({ ok: false, error: 'cannot consume' });

        // create transport for this socket if not exists (we expect client to call create-transport first)
        // find existing recv transport for this socket in the same room
        let recvTransportEntry = Object.values(transports).find(t => t.roomId === roomId && t.socketId === socket.id && t.transport.appData?.recv);
        if (!recvTransportEntry) {
          // No recv transport, client should call create-transport; but we can create server-side if desired
          return callback({ ok: false, error: 'no recv transport found; call create-transport first' });
        }

        const consumer = await recvTransportEntry.transport.consume({
          producerId,
          rtpCapabilities,
          paused: false
        });

        consumers[consumer.id] = { consumer, roomId, socketId: socket.id };

        callback({
          ok: true,
          params: {
            id: consumer.id,
            producerId,
            kind: consumer.kind,
            rtpParameters: consumer.rtpParameters
          }
        });
      } catch (err) {
        console.error('consume error', err);
        callback({ ok: false, error: err.message });
      }
    });

    // Pause/Resume/Close consumer handlers as needed...
    socket.on('mediasoup-resume', async ({ consumerId }, cb) => {
      try {
        const c = consumers[consumerId];
        if (!c) throw new Error('consumer not found');
        await c.consumer.resume();
        cb({ ok: true });
      } catch (err) { cb({ ok: false, error: err.message }); }
    });

    // Cleanup on disconnect
    socket.on('disconnect', () => {
      console.log('socket disconnected', socket.id);
      // Optionally cleanup transports/producers/consumers created by this socket
    });
  });
}

module.exports = { createWorker, setupSocketSignaling, ensureRouter, workerRef: () => worker };
