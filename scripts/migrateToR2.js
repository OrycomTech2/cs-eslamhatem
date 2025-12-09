const fs = require('fs').promises;
const path = require('path');
const { uploadToR2 } = require('../services/r2Service');

async function migrateFiles() {
  const uploadsDir = path.join(__dirname, '../uploads');
  
  try {
    // Read all files recursively
    const files = await getAllFiles(uploadsDir);
    
    for (const filePath of files) {
      const relativePath = path.relative(uploadsDir, filePath);
      const fileBuffer = await fs.readFile(filePath);
      const fileName = `migrated/${relativePath}`;
      
      try {
        const url = await uploadToR2(fileBuffer, fileName, getMimeType(filePath));
        console.log(`Uploaded: ${relativePath} -> ${url}`);
      } catch (error) {
        console.error(`Failed to upload ${relativePath}:`, error.message);
      }
    }
  } catch (error) {
    console.error('Migration error:', error);
  }
}

async function getAllFiles(dir) {
  const files = [];
  const items = await fs.readdir(dir, { withFileTypes: true });
  
  for (const item of items) {
    const fullPath = path.join(dir, item.name);
    if (item.isDirectory()) {
      files.push(...await getAllFiles(fullPath));
    } else {
      files.push(fullPath);
    }
  }
  
  return files;
}

function getMimeType(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  const mimeTypes = {
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.png': 'image/png',
    '.gif': 'image/gif',
    '.pdf': 'application/pdf',
    '.mp4': 'video/mp4',
    '.webm': 'video/webm',
    '.doc': 'application/msword',
    '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  };
  
  return mimeTypes[ext] || 'application/octet-stream';
}

migrateFiles();