const mongoose = require('mongoose');

const documentSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true
  },
  filePath: {
    type: String,
    required: true
  },
  fileType: {
    type: String,
    required: true
  },
  fileSize: {
    type: Number,
    required: true
  },
  sectionId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'DocumentSection',
    required: true
  },
  subsectionId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'DocumentSubsection',
    required: true
  }
}, { timestamps: true });

module.exports = mongoose.model('Document', documentSchema);