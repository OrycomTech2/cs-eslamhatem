// r2Service.js - CORRECTED VERSION
const { S3Client, PutObjectCommand, GetObjectCommand, DeleteObjectCommand } = require("@aws-sdk/client-s3");
const { getSignedUrl } = require("@aws-sdk/s3-request-presigner");
const { Upload } = require("@aws-sdk/lib-storage");

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

// Original upload function (single PUT)
exports.uploadToR2 = async (fileBuffer, fileName, contentType) => {
  try {
    console.log(`Starting R2 upload for: ${fileName} (${(fileBuffer.length / (1024 * 1024)).toFixed(2)} MB)`);
    
    const command = new PutObjectCommand({
      Bucket: BUCKET_NAME,
      Key: fileName,
      Body: fileBuffer,
      ContentType: contentType,
    });

    await S3.send(command);
    
    // Return the public URL
    return `https://pub-${process.env.CLOUDFLARE_PUBLIC_ENDPOINT}.r2.dev/${fileName}`;
  } catch (error) {
    console.error("R2 Upload Error:", error);
    throw new Error(`Failed to upload to R2: ${error.message}`);
  }
};

// Multipart upload for large files
exports.uploadToR2Multipart = async (fileBuffer, fileName, contentType, onProgress) => {
  try {
    console.log(`Starting multipart R2 upload for: ${fileName} (${(fileBuffer.length / (1024 * 1024)).toFixed(2)} MB)`);
    
    const parallelUploads3 = new Upload({
      client: S3, // Use the same S3Client instance
      params: {
        Bucket: BUCKET_NAME,
        Key: fileName,
        Body: fileBuffer,
        ContentType: contentType,
      },
      queueSize: 4, // Number of concurrent uploads
      partSize: 5 * 1024 * 1024, // 5MB chunks
      leavePartsOnError: false,
    });

    // Track progress
    if (onProgress) {
      parallelUploads3.on("httpUploadProgress", (progress) => {
        if (progress.total) {
          const percent = Math.round((progress.loaded / progress.total) * 100);
          console.log(`Upload progress: ${percent}%`);
          onProgress(percent);
        }
      });
    }

    const result = await parallelUploads3.done();
    console.log(`Multipart upload completed for: ${fileName}`);
    
    return `https://pub-${process.env.CLOUDFLARE_PUBLIC_ENDPOINT}.r2.dev/${fileName}`;
  } catch (error) {
    console.error("R2 Multipart Upload Error:", error);
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
  
  return `https://pub-${process.env.CLOUDFLARE_PUBLIC_ENDPOINT}.r2.dev/${fileName}`;
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

// Choose upload method based on file size
exports.uploadToR2Smart = async (fileBuffer, fileName, contentType, onProgress) => {
  const fileSizeMB = fileBuffer.length / (1024 * 1024);
  
  // Use multipart for files larger than 100MB
  if (fileSizeMB > 100) {
    console.log(`Large file detected (${fileSizeMB.toFixed(2)} MB), using multipart upload`);
    return await exports.uploadToR2Multipart(fileBuffer, fileName, contentType, onProgress);
  } else {
    console.log(`Small file detected (${fileSizeMB.toFixed(2)} MB), using standard upload`);
    return await exports.uploadToR2(fileBuffer, fileName, contentType);
  }
};
