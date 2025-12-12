// uploadProgress.js
const uploadProgress = new Map();

const progressService = {
  setProgress(uploadId, progress) {
    uploadProgress.set(uploadId, progress);
  },
  
  getProgress(uploadId) {
    return uploadProgress.get(uploadId) || 0;
  },
  
  removeProgress(uploadId) {
    uploadProgress.delete(uploadId);
  }
};

module.exports = progressService;
