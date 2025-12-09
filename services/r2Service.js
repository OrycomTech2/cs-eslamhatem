const { S3Client, PutObjectCommand, GetObjectCommand, DeleteObjectCommand } = require("@aws-sdk/client-s3");
const { getSignedUrl } = require("@aws-sdk/s3-request-presigner");

// Cloudflare R2 configuration
const S3 = new S3Client({
  region: "auto",
  endpoint: `https://${process.env.CLOUDFLARE_ACCOUNT_ID}.r2.cloudflarestorage.com`,
  credentials: {
    accessKeyId: process.env.CLOUDFLARE_ACCESS_KEY_ID,
    secretAccessKey: process.env.CLOUDFLARE_SECRET_ACCESS_KEY,
  },
});

const BUCKET_NAME = process.env.CLOUDFLARE_BUCKET_NAME || "cs-islamhatem";

// Upload file to R2
exports.uploadToR2 = async (fileBuffer, fileName, contentType) => {
  try {
    const command = new PutObjectCommand({
      Bucket: BUCKET_NAME,
      Key: fileName,
      Body: fileBuffer,
      ContentType: contentType,
    });

    await S3.send(command);
    
    // Return the public URL (adjust based on your R2 public domain)
    return `https://pub-${process.env.CLOUDFLARE_PUBLIC_ENDPOINT}.r2.dev/${fileName}`;
  } catch (error) {
    console.error("R2 Upload Error:", error);
    throw new Error(`Failed to upload to R2: ${error.message}`);
  }
};

// Get file URL from R2
exports.getFileUrl = async (fileName) => {
  try {
    if (!fileName) return null;
    
    // If it's already a full URL (from previous uploads), return as-is
    if (fileName.startsWith('http')) return fileName;
    
    // Otherwise, generate a signed URL
    const command = new GetObjectCommand({
      Bucket: BUCKET_NAME,
      Key: fileName,
    });
    
    // Generate a signed URL valid for 7 days
    const signedUrl = await getSignedUrl(S3, command, { expiresIn: 604800 });
    return signedUrl;
  } catch (error) {
    console.error("R2 Get URL Error:", error);
    return null;
  }
};

// Get public URL directly (if bucket is public)
exports.getPublicUrl = (fileName) => {
  if (!fileName) return null;
  
  // If it's already a full URL, return as-is
  if (fileName.startsWith('http')) return fileName;
  
  return `https://pub-291401bda2d0492a874e98b69b6cc9a7.r2.dev/${fileName}`;
};

// Delete file from R2
exports.deleteFromR2 = async (fileName) => {
  try {
    if (!fileName) return;
    
    // Extract just the filename if it's a URL
    const key = fileName.includes('/') 
      ? fileName.split('/').pop() 
      : fileName;
    
    const command = new DeleteObjectCommand({
      Bucket: BUCKET_NAME,
      Key: key,
    });
    
    await S3.send(command);
    return true;
  } catch (error) {
    console.error("R2 Delete Error:", error);
    throw new Error(`Failed to delete from R2: ${error.message}`);
  }
};

// Upload multiple files
exports.uploadMultipleToR2 = async (files) => {
  const uploadPromises = files.map(file => {
    return uploadToR2(file.buffer, file.filename, file.mimetype);
  });
  
  return Promise.all(uploadPromises);
};