const { AccessToken } = require('livekit-server-sdk');
require('dotenv').config();

module.exports = {
  createToken: (roomName, identity) => {
    const at = new AccessToken(
      process.env.LIVEKIT_API_KEY,
      process.env.LIVEKIT_API_SECRET,
      { identity }
    );

    at.addGrant({
      roomJoin: true,
      room: roomName,
      canPublish: true,
      canSubscribe: true,
    });

    return at.toJwt();
  }
};


module.exports = {
  LIVEKIT_URL: 'wss://orycom-ggnpyswy.livekit.cloud', // أو رابط السيرفر لو على Cloud
  LIVEKIT_API_KEY: 'APItU9YHYTdnW5a',
  LIVEKIT_API_SECRET: '35v4Lv1MKH4O3jtOiK2VOAoSiRlau6mnkak1dCMfcrP'
};