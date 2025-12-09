// models/WalletInfo.js
const mongoose = require('mongoose');
const walletInfoSchema = new mongoose.Schema({
  provider: { type: String, enum: ['instapay','vodafone_cash','etisalat_cash','orange_cash','telda'], required: true },
  displayName: String, // e.g., "Vodafone Cash"
  recipient: String, // the number or username to send to
  instructions: String, // optional extra text
});
module.exports = mongoose.model('WalletInfo', walletInfoSchema);
