require('dotenv').config({ path: '.env' });
const express = require('express');
const mongoose = require('mongoose');
const path = require('path');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const http = require('http');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { Server } = require('socket.io');
const { ExpressPeerServer } = require('peer');
const ChatRoom = require('./models/ChatRoom');
const searchRoutes = require("./routes/searchRoutes");

// Configuration
const PORT = 3000;
const FRONTEND_ORIGIN = process.env.CORS_ORIGIN || 'https://www.cs-islamhatem.com';
const MONGO_URI = process.env.MONGO_URI || '*';

// Initialize Server
const app = express();
const server = http.createServer(app);

// Enhanced Socket.IO Configuration
const io = new Server(server, {
  cors: {
    origin: [FRONTEND_ORIGIN, 'https://www.cs-islamhatem.com'],
    methods: ["GET", "POST"],
    credentials: true
  },
  transports: ['polling', 'websocket'],
  allowEIO3: true,
  connectionStateRecovery: {
    maxDisconnectionDuration: 120000
  },
  pingTimeout: 60000,
  pingInterval: 25000
});

// Middleware
// Update Helmet configuration in server.js
// In server.js - Update Helmet configuration
app.use(helmet({
  crossOriginResourcePolicy: false,
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: [
        "'self'",
        "'unsafe-inline'",
        "https://cdn.jsdelivr.net",
        "https://cdnjs.cloudflare.com",  // Add this
        "https://fonts.googleapis.com"   // Add this
      ],
      scriptSrc: [
        "'self'",
        "'unsafe-inline'",
        "'unsafe-eval'",
        "https://cdn.jsdelivr.net"
      ],
      scriptSrcAttr: ["'unsafe-inline'"],
      fontSrc: [
        "'self'", 
        "https://cdn.jsdelivr.net",
        "https://fonts.gstatic.com"      // Add this for Google Fonts
      ],
      imgSrc: ["'self'", "data:", "blob:", "https:"],
      connectSrc: [
        "'self'", 
        "https://cdn.jsdelivr.net",
        "https://*.r2.cloudflarestorage.com",  // Fix: Wildcard only at start
        "https://pub-*.r2.dev",
        "wss://*.r2.cloudflarestorage.com"
      ],
      frameSrc: ["'self'"],
      mediaSrc: ["'self'", "blob:", "https:"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"]
    }
  }
}));

app.use(cors({
  origin: [FRONTEND_ORIGIN, 'https://www.cs-islamhatem.com','https://*.r2.cloudflarestorage.com'],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
  credentials: true,
  allowedHeaders: ['Content-Type', 'Authorization', 'x-amz-*']
}));

app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', FRONTEND_ORIGIN);
  res.header('Access-Control-Allow-Credentials', 'true');
  next();
});

const upload = multer({
  limits: { fileSize: 10 * 1024 * 1024 * 1024 } // 10 GB in bytes
});


const limiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 1000,
  skip: (req) => req.url.startsWith('/uploads')
});
app.use(limiter);

app.use(express.json({ limit: '10gb' }));
app.use(express.urlencoded({ limit: '10gb', extended: true }));


// Static files
app.use(express.static(path.join(__dirname, 'public')));
  

// Database Connection
mongoose.connect(MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  serverSelectionTimeoutMS: 5000,
  socketTimeoutMS: 45000,
  retryWrites: true,
  w: 'majority'
})
.then(() => console.log('✅ MongoDB connected'))
.catch(err => console.error('❌ MongoDB connection error:', err));

// Enhanced Socket.IO Middleware
io.use((socket, next) => {
  try {
    // Development bypass
    if (process.env.NODE_ENV !== 'production') {
      if (socket.handshake.query.adminId) {
        socket.user = { id: socket.handshake.query.adminId, role: 'admin' };
        return next();
      }
      if (socket.handshake.query.studentId) {
        socket.user = { id: socket.handshake.query.studentId, role: 'student' };
        return next();
      }
    }

    // Production authentication
    const token = socket.handshake.auth?.token ||
                  socket.handshake.query?.token ||
                  (socket.handshake.headers.authorization || '').replace('Bearer ','');
    if (!token) return next(new Error('Authentication required'));
    
    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
      if (err) return next(new Error('Invalid token'));
      
      socket.user = {
        id: decoded.userId || decoded.assistantId || decoded.adminId || decoded._id || decoded.id,
        role: decoded.role || decoded.userRole || decoded.type || 'user',
        ...decoded
      };
      
      next();
    });
  } catch (err) {
    next(new Error('Authentication error'));
  }
});

// Room Management
const activeRooms = {};
app.set("activeRooms", activeRooms);
app.set("io", io);

const User = require("./models/User");
const Course = require("./models/Course");
const Admin = require('./models/Admin');
const Assistant = require('./models/Assistant');


io.on("connection", (socket) => {
  console.log(`⚡ ${socket.user?.role} connected [${socket.id}] via ${socket.conn.transport.name}`);

  // ========== Live Classroom Functionality ==========
  // Unified room creation for both admin and assistant
  socket.on("create-room", async (data, callback) => {
    try {
      const { roomId, courseId } = data;
      const userId = socket.user?.id;
      const userRole = socket.user?.role;

      if (!roomId || !courseId || !userId) {
        throw new Error("Missing required fields");
      }

      // Check if room already exists FIRST
      if (activeRooms[roomId]) {
        throw new Error("Room already exists");
      }

      // Check if user has permission to create rooms
      if (!['admin', 'assistant'].includes(userRole)) {
        throw new Error("Only admins and assistants can create rooms");
      }

      // Fetch course title
      const course = await Course.findById(courseId).select("title");
      if (!course) throw new Error("Invalid course");

      let instructorName = "";
      let instructorData = {};
      
      // Fetch instructor details based on role
      if (userRole === 'admin') {
        const admin = await Admin.findById(userId).select("username");
        if (!admin) throw new Error("Admin not found");
        instructorName = admin.username;
        instructorData = {
          adminId: userId,
          adminName: instructorName,
          adminSocket: socket.id
        };
      } else if (userRole === 'assistant') {
        const assistant = await Assistant.findById(userId).select("name");
        if (!assistant) throw new Error("Assistant not found");
        instructorName = assistant.name;
        instructorData = {
          assistantId: userId,
          assistantName: instructorName,
          assistantSocket: socket.id
        };
      }

      // Create room with appropriate instructor data
      activeRooms[roomId] = {
        courseId,
        courseTitle: course.title,
        instructorRole: userRole,
        createdAt: new Date(),
        status: "active",
        students: {},
        ...instructorData
      };

      socket.join(roomId);

      console.log(`🏫 Room created: ${roomId} for "${course.title}" by ${userRole} ${instructorName}`);

      const responseData = {
  status: "success", 
  roomId, 
  courseTitle: course.title,
  instructorName: instructorName,  // This must be included
  instructorRole: userRole         // This should also be included
};

callback?.(responseData);
socket.emit("room-created", responseData); // Make sure this line exists

    } catch (err) {
      console.error("Room creation error:", err);
      callback?.({ error: err.message });
    }
  });

  // Student joins room
  socket.on("join-room", async (data, callback) => {
    try {
      const { roomId } = data;
      const studentId = socket.user?.id;
      const studentRole = socket.user?.role;

      if (!activeRooms[roomId]) {
        return callback?.({ error: "Room does not exist or has ended" });
      }

      if (activeRooms[roomId].students[studentId]) {
        return callback?.({ error: "You are already in this room" });
      }

      let studentName = socket.user?.name || `Student ${studentId.substring(0, 8)}`;
      
      // For anonymous users, we don't need to query the database
      if (studentRole === 'student' && /^[0-9a-fA-F]{24}$/.test(studentId)) {
        // Only query database for valid MongoDB ObjectIds
        try {
          const student = await User.findById(studentId).select("name");
          if (student) {
            studentName = student.name || studentName;
          }
        } catch (dbErr) {
          console.log("Student not found in database, using provided name");
        }
      }

      socket.join(roomId);

      // Save student with name
      activeRooms[roomId].students[studentId] = { 
        socketId: socket.id, 
        name: studentName,
      };

      io.to(roomId).emit("user-joined", { id: studentId, name: studentName });
      console.log(`🎓 ${studentName} joined room ${roomId}`);

      callback?.({ status: "success", roomId, studentName });
    } catch (err) {
      console.error("Join room error:", err);
      callback?.({ error: err.message });
    }
  });

  // WebRTC Signaling
  socket.on("webrtc-offer", (data) => {
    try {
      const { roomId, studentId, sdp } = data;
      const room = activeRooms[roomId];

      if (!room || !room.students[studentId]) {
        throw new Error("Invalid room or student");
      }

      io.to(room.students[studentId].socketId).emit("webrtc-offer", {
        from: socket.id,
        sdp,
        roomId,
      });
    } catch (e) {
      console.error("webrtc-offer error", e);
    }
  });

  socket.on("webrtc-answer", (data) => {
    try {
      const { roomId, sdp } = data;
      const room = activeRooms[roomId];
      if (!room) throw new Error("Room not found");

      // Determine the instructor socket based on role
      const instructorSocket = room.adminSocket || room.assistantSocket;
      if (!instructorSocket) throw new Error("Instructor not found in room");

      io.to(instructorSocket).emit("webrtc-answer", {
        from: socket.id,
        sdp,
        roomId,
        student: { id: socket.user?.id, name: socket.user?.name },
      });
    } catch (e) {
      console.error("webrtc-answer error", e);
    }
  });

  // ICE candidates
  socket.on("ice-candidate", (data) => {
    try {
      const { roomId, candidate, studentId } = data;
      const room = activeRooms[roomId];
      if (!room) throw new Error("Room not found");

      let targetSocket;
      if (studentId) {
        targetSocket = room.students[studentId]?.socketId;
      } else {
        // Send to instructor (admin or assistant)
        targetSocket = room.adminSocket || room.assistantSocket;
      }

      if (targetSocket) {
        io.to(targetSocket).emit("ice-candidate", {
          from: socket.id,
          candidate,
          roomId,
          studentId: studentId || socket.user?.id,
        });
      }
    } catch (e) {
      console.error("ice-candidate error", e);
    }
  });

  // Chat messages
  socket.on("send-message", async (roomId, message) => {
  try {
    if (activeRooms[roomId]) {
      let senderName = "Anonymous";
      
      // Check if sender is an instructor (admin or assistant)
      const room = activeRooms[roomId];
      if (room && (room.adminSocket === socket.id || room.assistantSocket === socket.id)) {
        // This is an instructor - get their name from room data
        senderName = room.adminName || room.assistantName || "Instructor";
      } else if (socket.user?.id) {
        // This is a student - try to get their name
        const student = room.students[socket.user.id];
        senderName = student?.name || `Student ${socket.user.id.substring(0, 8)}`;
        
        // For students not in the room students list, try to get from database
        if (senderName.includes("Student") && socket.user.role === 'student') {
          try {
            const user = await User.findById(socket.user.id).select("name");
            if (user) senderName = user.name || senderName;
          } catch (dbErr) {
            console.log("Could not fetch student name from DB");
          }
        }
      }
      
      io.to(roomId).emit("new-message", { 
        sender: senderName, 
        message,
        isInstructor: (room.adminSocket === socket.id || room.assistantSocket === socket.id)
      });
    }
  } catch (err) {
    console.error("Error handling message:", err);
  }
});

  // Instructor controls
  socket.on("instructor-mute-student", ({ roomId, targetId, mute }) => {
    const room = activeRooms[roomId];
    
    // Check if socket belongs to instructor of this room (admin or assistant)
    const isInstructor = room && (
      (room.adminSocket && room.adminSocket === socket.id) ||
      (room.assistantSocket && room.assistantSocket === socket.id)
    );
    
    if (!isInstructor) return;

    const studentSocket = room.students[targetId]?.socketId;
    if (!studentSocket) return;

    io.to(studentSocket).emit(mute ? "force-mute" : "force-unmute");
    
    const instructorName = room.adminName || room.assistantName;
    console.log(`Instructor ${instructorName} ${mute ? "muted" : "unmuted"} student ${room.students[targetId]?.name}`);
  });

  socket.on("instructor-kick-student", ({ roomId, targetId }) => {
    const room = activeRooms[roomId];
    
    // Check if socket belongs to instructor of this room (admin or assistant)
    const isInstructor = room && (
      (room.adminSocket && room.adminSocket === socket.id) ||
      (room.assistantSocket && room.assistantSocket === socket.id)
    );
    
    if (!isInstructor) return;

    const studentSocket = room.students[targetId]?.socketId;
    if (!studentSocket) return;

    io.to(studentSocket).emit("force-kick");

    const studentName = room.students[targetId]?.name;
    delete room.students[targetId];

    io.to(roomId).emit("user-left", { id: targetId, name: studentName });
    
    const instructorName = room.adminName || room.assistantName;
    console.log(`Instructor ${instructorName} kicked student ${studentName}`);
  });

  // Emoji reactions
  socket.on('send-emoji', (data) => {
  try {
    const { roomId, emoji } = data;
    
    if (activeRooms[roomId]) {
      let senderName = "Anonymous";
      
      // Check if sender is an instructor (admin or assistant)
      const room = activeRooms[roomId];
      if (room && (room.adminSocket === socket.id || room.assistantSocket === socket.id)) {
        // This is an instructor - get their name from room data
        senderName = room.adminName || room.assistantName || "Instructor";
      } else if (socket.user?.id) {
        // This is a student - try to get their name
        const student = room.students[socket.user.id];
        senderName = student?.name || `Student ${socket.user.id.substring(0, 8)}`;
      }
      
      io.to(roomId).emit('receive-emoji', senderName, emoji);
    }
  } catch (err) {
    console.error('Emoji send error:', err);
  }
});

  // Hand raising
  socket.on('raise-hand', (roomId) => {
    if (activeRooms[roomId]) {
      const studentId = socket.user?.id;
      const studentName = socket.user?.name || `Student ${studentId.substring(0, 8)}`;
      
      if (studentId) {
        // Send to instructor (admin or assistant)
        const instructorSocket = activeRooms[roomId].adminSocket || activeRooms[roomId].assistantSocket;
        if (instructorSocket) {
          io.to(instructorSocket).emit('student-raised-hand', { 
            id: studentId, 
            name: studentName 
          });
        }
      }
    }
  });

  socket.on('lower-hand', (roomId) => {
    if (activeRooms[roomId]) {
      const studentId = socket.user?.id;
      const studentName = socket.user?.name || `Student ${studentId.substring(0, 8)}`;
      
      if (studentId) {
        // Send to instructor (admin or assistant)
        const instructorSocket = activeRooms[roomId].adminSocket || activeRooms[roomId].assistantSocket;
        if (instructorSocket) {
          io.to(instructorSocket).emit('student-lowered-hand', { 
            id: studentId, 
            name: studentName 
          });
        }
      }
    }
  });

  // Task distribution
  socket.on('send-task', (data) => {
    try {
      const { roomId, taskData } = data;
      
      if (activeRooms[roomId]) {
        // Check if sender is instructor (admin or assistant)
        const isInstructor = activeRooms[roomId] && (
          activeRooms[roomId].adminSocket === socket.id ||
          activeRooms[roomId].assistantSocket === socket.id
        );
        
        if (isInstructor) {
          io.to(roomId).emit('receive-task', taskData);
        }
      }
    } catch (err) {
      console.error('Task send error:', err);
    }
  });

  socket.on('submit-task', (data) => {
    try {
      const { roomId, submissionData } = data;
      
      if (activeRooms[roomId]) {
        const studentId = socket.user?.id;
        const studentName = socket.user?.name || `Student ${studentId.substring(0, 8)}`;
        
        if (studentId) {
          // Send to instructor (admin or assistant)
          const instructorSocket = activeRooms[roomId].adminSocket || activeRooms[roomId].assistantSocket;
          if (instructorSocket) {
            io.to(instructorSocket).emit('task-submitted', {
              studentId,
              studentName,
              submission: submissionData
            });
          }
        }
      }
    } catch (err) {
      console.error('Task submission error:', err);
    }
  });

  // Chat functionality
  socket.on('chat:join', async (roomId) => {
    try {
      const room = await ChatRoom.findById(roomId);
      if (!room) return;
      socket.join(roomId);
      socket.emit('chat:joined', roomId);
      
      const userName = socket.user?.name || `User ${socket.user?.id.substring(0, 8)}`;
      console.log(`💬 ${userName} joined chat room ${roomId}`);
    } catch (err) {
      console.error('Chat join error:', err);
    }
  });

  socket.on('chat:leave', (roomId) => {
    socket.leave(roomId);
    
    const userName = socket.user?.name || `User ${socket.user?.id.substring(0, 8)}`;
    console.log(`💬 ${userName} left chat room ${roomId}`);
  });

  socket.on('chat:message', async (data) => {
    try {
      const { roomId, message } = data;
      
      if (!socket.rooms.has(roomId)) {
        return socket.emit('chat:error', 'Not in this room');
      }

      // Save message to database
      const chatRoom = await ChatRoom.findByIdAndUpdate(
        roomId,
        { $push: { messages: { 
          sender: socket.user.id, 
          senderName: socket.user.name,
          content: message 
        } } },
        { new: true }
      );

      if (!chatRoom) {
        return socket.emit('chat:error', 'Room not found');
      }

      // Broadcast to all in room except sender
      socket.to(roomId).emit('chat:message', {
        sender: socket.user.id,
        senderName: socket.user.name,
        message,
        timestamp: new Date()
      });

      // Send back to sender with success
      socket.emit('chat:message:sent', {
        sender: socket.user.id,
        senderName: socket.user.name,
        message,
        timestamp: new Date()
      });

    } catch (err) {
      console.error('Chat message error:', err);
      socket.emit('chat:error', 'Failed to send message');
    }
  });

  // Leave room
  socket.on('leave-room', (roomId) => {
    if (!activeRooms[roomId]) return;
    
    // Check if this is an instructor (admin or assistant) leaving
    const isInstructor = activeRooms[roomId] && (
      activeRooms[roomId].adminSocket === socket.id ||
      activeRooms[roomId].assistantSocket === socket.id
    );
    
    if (isInstructor) {
      // Instructor leaving - end room
      io.to(roomId).emit('room-ended');
      delete activeRooms[roomId];
      
      const instructorName = activeRooms[roomId]?.adminName || activeRooms[roomId]?.assistantName;
      console.log(`🚪 Room ${roomId} ended by instructor ${instructorName}`);
    } else {
      // Student leaving
      const studentId = socket.user?.id;
      if (studentId && activeRooms[roomId]?.students[studentId]) {
        const studentName = activeRooms[roomId].students[studentId]?.name;
        delete activeRooms[roomId].students[studentId];
        io.to(roomId).emit('user-left', { id: studentId, name: studentName });
        console.log(`🎓 Student ${studentName} left room ${roomId}`);
      }
    }
  });

  // Disconnect handler
  socket.on("disconnect", () => {
    console.log(`⚠️ ${socket.user?.role} disconnected [${socket.id}]`);

    for (const roomId in activeRooms) {
      const room = activeRooms[roomId];

      // Check if disconnecting socket is an instructor (admin or assistant)
      const isInstructor = room && (
        room.adminSocket === socket.id ||
        room.assistantSocket === socket.id
      );

      if (isInstructor) {
        io.to(roomId).emit("room-ended");
        delete activeRooms[roomId];
        
        const instructorName = room.adminName || room.assistantName;
        const instructorRole = room.instructorRole;
        console.log(`🚪 Room ${roomId} ended (${instructorRole} ${instructorName} disconnected)`);
        continue;
      }

      // Handle student disconnection
      for (const studentId in room.students) {
        if (room.students[studentId].socketId === socket.id) {
          const studentName = room.students[studentId].name;
          delete room.students[studentId];
          io.to(roomId).emit("user-left", { id: studentId, name: studentName });
          console.log(`🎓 Student ${studentName} disconnected from ${roomId}`);
          break;
        }
      }

      // Clean up empty rooms
      if (Object.keys(room.students).length === 0 && 
          !(room.adminSocket === socket.id || room.assistantSocket === socket.id)) {
        delete activeRooms[roomId];
        console.log(`🧹 Cleaned up empty room ${roomId}`);
      }
    }
  });
});

app.use('/api/auth', require('./routes/authRoutes'));
app.use('/api/users', require('./routes/userRoutes'));
app.use('/api/admin', require('./routes/adminRoutes')); // Islam Hatem only
app.use('/api/courses', require('./routes/courseRoutes'));
app.use('/api/lessons', require('./routes/lessonRoutes'));
app.use('/api/assignments', require('./routes/assignmentRoutes'));
app.use('/api/live', require('./routes/liveRoutes'));
app.use('/api/chat', require('./routes/chatRoutes'));
app.use('/api/help', require('./routes/helpRoutes'));
app.use('/api/assistant', require("./routes/assistantRoutes"));
app.use('/api/courses', require("./routes/courseRoutes"));
app.use('/api/lessons', require("./routes/lessonRoutes"));
app.use('/api/assignments', require("./routes/assignmentRoutes"));
app.use('/api/payment-requests', require('./routes/paymentRequestRoutes'));
app.use('/api/r2', require('./routes/r2Routes'));

app.use('/api/live', require("./routes/liveRoutes"));
app.use('/api/chat', require("./routes/chatRoutes"));
app.use('/api/help', require("./routes/helpRoutes"));
app.use('/api/quizzes', require("./routes/quizRoutes"));
// server.js - Add these lines after middleware setup
app.get('/', (req, res) => {
  res.sendFile(__dirname + '/upload-page/index.html');
});

// Serve static files for upload page
app.use('/upload-page', express.static(path.join(__dirname, 'upload-page')));

// Add upload routes
const { uploadToR2, deleteFromR2, uploadToR2Smart, S3, BUCKET_NAME,getSignedUrl } = require('./services/r2Service');
const Video = require('./models/Video');
const uploadMemory = require('./middleware/multerMemory');

// Video upload endpoint
// Update the upload endpoint
// Update the upload endpoint in server.js
// Video upload endpoint - CORRECTED VERSION
const {
  CreateMultipartUploadCommand,
} = require("@aws-sdk/client-s3");

app.post("/api/upload/init", async (req, res) => {
  try {
    const { fileName, fileType, title } = req.body;

    if (!fileName || !fileType || !title) {
      return res.status(400).json({ error: "Missing fields" });
    }

    const safeName = fileName
      .replace(/\s+/g, "-")
      .replace(/[^a-zA-Z0-9.-]/g, "");

    const key = `videos/${Date.now()}_${safeName}`;

    const command = new CreateMultipartUploadCommand({
      Bucket: BUCKET_NAME,
      Key: key,
      ContentType: fileType,
    });

    const result = await S3.send(command);

    res.json({
      uploadId: result.UploadId,
      key,
    });

  } catch (err) {
    console.error("INIT error:", err);
    res.status(500).json({ error: "Failed to init multipart upload" });
  }
});

const {
  UploadPartCommand,
} = require("@aws-sdk/client-s3");

app.post("/api/upload/part-url", async (req, res) => {
  try {
    const { uploadId, key, partNumber } = req.body;

    if (!uploadId || !key || !partNumber) {
      return res.status(400).json({ error: "Missing parameters" });
    }

    const command = new UploadPartCommand({
      Bucket: BUCKET_NAME,
      Key: key,
      UploadId: uploadId,
      PartNumber: partNumber,
    });

    const url = await getSignedUrl(S3, command, {
      expiresIn: 900, // 15 minutes
    });

    res.json({ url });

  } catch (err) {
    console.error("PART URL error:", err);
    res.status(500).json({ error: "Failed to generate part URL" });
  }
});

const {
  CompleteMultipartUploadCommand,
} = require("@aws-sdk/client-s3");

app.post("/api/upload/complete", async (req, res) => {
  const { uploadId, key, parts, title } = req.body;

  if (!uploadId || !key || !Array.isArray(parts)) {
    return res.status(400).json({ error: "Invalid completion data" });
  }

  // 🚀 Respond immediately (Fly timeout safe)
  res.status(202).json({ success: true });

  try {
    const command = new CompleteMultipartUploadCommand({
      Bucket: BUCKET_NAME,
      Key: key,
      UploadId: uploadId,
      MultipartUpload: {
        Parts: parts, // [{ PartNumber, ETag }]
      },
    });

    await S3.send(command);

    await Video.create({
      title: title || "Untitled",
      url: `https://pub-${process.env.CLOUDFLARE_PUBLIC_ENDPOINT}.r2.dev/${key}`,
      uploadedBy: req.user?.id,
    });

    console.log("Multipart upload completed:", key);

  } catch (err) {
    console.error("COMPLETE error:", err);
  }
});



app.get('/api/videos', async (req, res) => {
  try {
    const videos = await Video.find()
      .sort({ createdAt: -1 })
      .select('title url size contentType createdAt')
      .lean();

    res.json({
      success: true,
      count: videos.length,
      data: videos
    });
  } catch (error) {
    console.error('Error fetching videos:', error);
    res.status(500).json({ error: 'Failed to fetch videos' });
  }
});

// Delete video
app.delete('/api/videos/:id', async (req, res) => {
  try {
    const video = await Video.findById(req.params.id);
    
    if (!video) {
      return res.status(404).json({ error: 'Video not found' });
    }

    // Extract filename from URL for deletion
    const fileName = video.url.split('/').pop();
    
    // Delete from R2
    await deleteFromR2(fileName);
    
    // Delete from MongoDB
    await Video.findByIdAndDelete(req.params.id);

    res.json({
      success: true,
      message: 'Video deleted successfully'
    });
  } catch (error) {
    console.error('Delete error:', error);
    res.status(500).json({ error: 'Failed to delete video' });
  }
});

// Get upload progress endpoint (for large file handling)
app.get('/api/upload/progress/:uploadId', (req, res) => {
  // You can implement progress tracking with Redis or in-memory store
  const progress = uploadProgress[req.params.uploadId] || 0;
  res.json({ progress });
});

// Serve upload page
app.get('/admin/upload-videos', (req, res) => {
  res.sendFile(path.join(__dirname, 'upload-page', 'index.html'));
});


const uploadStatus = {};

// Status endpoint for polling
app.get('/api/upload/status/:uploadId', (req, res) => {
  const status = uploadStatus[req.params.uploadId] || {
    status: 'unknown',
    progress: 0,
    message: 'Upload not found'
  };
  
  res.json(status);
});

// Clean up old status entries periodically
setInterval(() => {
  const oneHourAgo = Date.now() - (60 * 60 * 1000);
  for (const [uploadId, status] of Object.entries(uploadStatus)) {
    if (status.timestamp && status.timestamp < oneHourAgo) {
      delete uploadStatus[uploadId];
    }
  }
}, 30 * 60 * 1000); // Every 30 minutes

// Active rooms endpoint
app.get('/api/active-rooms', (req, res) => {
  res.json({
    status: 'success',
    data: Object.keys(activeRooms).map(roomId => ({
      roomId,
      courseId: activeRooms[roomId].courseId,
      adminId: activeRooms[roomId].adminId,
      studentCount: Object.keys(activeRooms[roomId].students).length,
      createdAt: activeRooms[roomId].createdAt
    }))
  });
});

// Chat rooms endpoint
app.get('/api/chat-rooms', async (req, res) => {
  try {
    const rooms = await ChatRoom.find().populate('participants');
    res.json({ status: 'success', data: rooms });
  } catch (err) {
    res.status(500).json({ status: 'error', message: err.message });
  }
});

// Root endpoint
app.get('/', (req, res) => {
  res.send('Backend is working 🎉');
});

// PeerJS Server with enhanced configuration
const peerServer = ExpressPeerServer(server, {
  debug: true,
  path: '/peerjs',
  proxied: true,
  alive_timeout: 60000,
  concurrent_limit: 5000,
  allow_discovery: true
});

app.use('/peerjs', peerServer);

// WebRTC status endpoint
app.get('/api/webrtc-status', (req, res) => {
  res.json({
    status: 'active',
    activeRooms: Object.keys(activeRooms).length,
    iceServers: [{ urls: 'stun:stun.l.google.com:19302' }]
  });
});

// Error Handling
app.use((err, req, res, next) => {
  console.error(err.stack);
  
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(413).json({ 
        message: 'File too large. Maximum size is 100MB' 
      });
    }
  }
  
  res.status(500).json({ 
    status: 'error',
    message: err.message || 'Internal Server Error',
    stack: process.env.NODE_ENV === 'development' ? err.stack : undefined
  });
});

// Start Server
server.listen(PORT, '0.0.0.0', () => {
  console.log(`
    🚀 Server running on ://localhost:${PORT}
    📡 Socket.IO: ws://localhost:${PORT}/socket.io/
    🎮 PeerJS: ://localhost:${PORT}/peerjs
    💬 Chat: ws://localhost:${PORT}
    🌐 CORS Origin: ${FRONTEND_ORIGIN}
    🏫 Active rooms: ${Object.keys(activeRooms).length}
  `);
});

// Cleanup on shutdown
process.on('SIGTERM', () => {
  console.log('🛑 Server shutting down...');
  server.close(() => {
    mongoose.connection.close(false, () => {
      console.log('🔴 MongoDB connection closed');
      process.exit(0);
    });
  });
});



