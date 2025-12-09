const express = require("express");
const router = express.Router();
const { S3Client, PutObjectCommand } = require("@aws-sdk/client-s3");
const { getSignedUrl } = require("@aws-sdk/s3-request-presigner");
const Video = require("../models/Video");

const r2 = new S3Client({
  region: "auto",
  endpoint: `https://${process.env.CLOUDFLARE_ACCOUNT_ID}.r2.cloudflarestorage.com`,
  credentials: {
    accessKeyId: process.env.CLOUDFLARE_ACCESS_KEY_ID,
    secretAccessKey: process.env.CLOUDFLARE_SECRET_ACCESS_KEY,
  },
});

// 1) GET presigned URL
router.get("/upload-url", async (req, res) => {
  try {
    const { filename, contentType } = req.query;

    const key = `videos/${Date.now()}_${filename}`;

    const command = new PutObjectCommand({
      Bucket: process.env.CLOUDFLARE_BUCKET_NAME,
      Key: key,
      ContentType: contentType,
    });

    const uploadUrl = await getSignedUrl(r2, command, { expiresIn: 3600 });

    res.json({
      uploadUrl,
      fileUrl: `${process.env.R2_PUBLIC_URL}/${key}`,
    });
  } catch (err) {
    console.error("Error generating presigned URL:", err);
    res.status(500).json({ error: "Failed to generate upload URL" });
  }
});

// 2) Save the video details to DB
router.post("/save-video", async (req, res) => {
  try {
    const { title, url, size, contentType, adminId } = req.body;

    const video = await Video.create({
      title,
      url,
      size,
      contentType,
      uploadedBy: adminId || null,
    });

    res.json({ success: true, video });
  } catch (err) {
    console.error("Save video error:", err);
    res.status(500).json({ error: "Failed to save video" });
  }
});

module.exports = router;
