// utils/turnCreds.js
const crypto = require('crypto');

function generateTurnCredentials({ usernamePrefix = '', ttl = 3600, secret, realm }) {
  const expires = Math.floor(Date.now() / 1000) + ttl;
  const username = `${usernamePrefix}${expires}`; // e.g., "user_162..."
  const hmac = crypto.createHmac('sha1', secret).update(username).digest('base64');
  const credential = hmac;
  return { username, credential, ttl, realm };
}

module.exports = generateTurnCredentials;
