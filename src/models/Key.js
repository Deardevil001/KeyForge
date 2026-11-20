import mongoose from 'mongoose';

const keySchema = new mongoose.Schema({
  keyHash: {
    type: String,
    required: true,
    unique: true
  },
  encryptedKey: {
    type: String,
    required: true
  },
  keyHint: {
    type: String,
    required: true
  },
  type: {
    type: String,
    enum: ['admin', 'user'],
    required: true
  },
  owner: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    default: null
  },
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },

  // Optional for compatibility with older keys.
  // New key generation must still require both Device ID and App ID.
  deviceId: {
    type: String,
    default: null,
    trim: true,
    maxlength: 256
  },
  appId: {
    type: String,
    default: null,
    trim: true,
    maxlength: 128
  },

  status: {
    type: String,
    enum: ['active', 'inactive', 'revoked'],
    default: 'active',
    required: true
  },
  expiresAt: {
    type: Date,
    required: true
  },
  boundAt: {
    type: Date,
    default: null
  },
  deactivatedAt: {
    type: Date,
    default: null
  },
  revokedAt: {
    type: Date,
    default: null
  },
  lastVerifiedAt: {
    type: Date,
    default: null
  }
}, {
  timestamps: true
});

// The owner index also supports queries beginning with owner.
// Keep indexes focused to avoid redundant index definitions.
keySchema.index({ owner: 1, createdAt: -1 });
keySchema.index({ deviceId: 1, appId: 1 });
keySchema.index({ status: 1, expiresAt: 1 });

export default mongoose.model('Key', keySchema);