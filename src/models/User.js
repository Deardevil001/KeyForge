import mongoose from 'mongoose';

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true,
    maxlength: 80
  },
  email: {
  type: String,
  required: true,
  unique: true,
  lowercase: true,
  trim: true,
  maxlength: 254,
  match: /^[^\s@]+@[^\s@]+\.[^\s@]+$/
},
  passwordHash: {
    type: String,
    required: true
  },
  role: {
    type: String,
    enum: ['admin', 'user'],
    default: 'user',
    required: true
  },
  // Default free-key generation limit for newly created users.
  keyLimit: {
    type: Number,
    default: 25,
    min: 0,
    max: 1000,
    validate: {
      validator: Number.isInteger,
      message: 'keyLimit must be an integer.'
    }
  },
  // Separate admin-granted permission to bypass keyLimit.
  // Existing custom-key permission remains unchanged.
  unlimitedKeyAccess: {
    type: Boolean,
    default: false
  },
  disabled: {
    type: Boolean,
    default: false
  },
  // Incremented after password reset to invalidate previously issued sessions.
  sessionVersion: {
    type: Number,
    default: 0,
    min: 0,
    validate: {
      validator: Number.isInteger,
      message: 'sessionVersion must be an integer.'
    }
  }
}, {
  timestamps: true
});

export default mongoose.model('User', userSchema);