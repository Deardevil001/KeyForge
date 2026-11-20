import mongoose from 'mongoose';

const accountVerificationSchema = new mongoose.Schema({
  owner: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    unique: true
  },

  // SHA-256 digest used to validate submitted strings.
  secretHash: {
    type: String,
    required: true
  },

  // AES-256-GCM encrypted original string, needed to show it again in the UI.
  encryptedSecret: {
    type: String,
    required: true
  },

  status: {
    type: String,
    enum: ['active', 'revoked'],
    default: 'active'
  },

  generation: {
    type: Number,
    default: 1
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

// Exactly one account-verification record per account.
accountVerificationSchema.index({ owner: 1 }, { unique: true });

export default mongoose.model(
  'AccountVerification',
  accountVerificationSchema
);