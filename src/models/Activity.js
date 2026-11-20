import mongoose from 'mongoose';

const activitySchema = new mongoose.Schema({
  actor: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    default: null
  },
  action: {
    type: String,
    required: true,
    trim: true,
    maxlength: 80
  },
  details: {
    type: String,
    required: true,
    trim: true,
    maxlength: 240
  },
  keyId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Key',
    default: null
  }
}, {
  timestamps: true
});

// After a log is saved, permanently remove all but the newest 10 records.
// This keeps the collection trimmed even when the admin activity page is
// not opened. The admin route also limits its response to the newest 10.
activitySchema.post('save', async function () {
  const Activity = this.constructor;

  const newestLogs = await Activity.find({})
    .sort({ createdAt: -1, _id: -1 })
    .select('_id')
    .limit(10)
    .lean();

  const keepIds = newestLogs.map((item) => item._id);

  await Activity.deleteMany({
    _id: { $nin: keepIds }
  });
});

export default mongoose.model('Activity', activitySchema);