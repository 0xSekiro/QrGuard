// models/LinkScan.js
const mongoose = require("mongoose");

const LinkScanSchema = new mongoose.Schema(
  {
    // 1️⃣ id (MongoDB auto-generated)
    // _id is created automatically

    // 2️⃣ link as STRING
    link: {
      type: String,
      required: true,
      trim: true,
    },

    // 3️⃣ response as STRING
    response: {
      type: String,
      required: true,
    },

    // 4️⃣ created at DATE
    createdAt: {
      type: Date,
      default: Date.now,
    },
  },
  {
    versionKey: false,
  }
);

module.exports = mongoose.model("LinkScan", LinkScanSchema);
