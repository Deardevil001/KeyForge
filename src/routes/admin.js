import { Router } from 'express';
import mongoose from 'mongoose';
import User from '../models/User.js';
import Key from '../models/Key.js';
import Activity from '../models/Activity.js';
import { requireAuth, requireAdmin } from '../middleware/auth.js';
import { safeUser } from '../utils/security.js';

const router = Router();

// Every route in this file is restricted to authenticated administrators.
router.use(requireAuth, requireAdmin);

router.get('/users', async (_req, res, next) => {
  try {
    const [users, counts] = await Promise.all([
      User.find({}).sort({ createdAt: -1 }),
      Key.aggregate([
        { $group: { _id: '$owner', count: { $sum: 1 } } }
      ])
    ]);

    const countByOwner = new Map(
      counts.map((item) => [String(item._id), item.count])
    );

    return res.json({
      users: users.map((user) => ({
        ...safeUser(user),
        keyCount: countByOwner.get(String(user._id)) || 0,
        createdAt: user.createdAt
      }))
    });
  } catch (error) {
    return next(error);
  }
});

// Permanently delete a regular user and their owned keys.
// Admin accounts are protected from deletion.
router.delete('/users/:id', async (req, res, next) => {
  try {
    const { id } = req.params;

    if (!mongoose.isValidObjectId(id)) {
      return res.status(400).json({ error: 'Invalid user ID.' });
    }

    const user = await User.findById(id);

    if (!user || user.role === 'admin') {
      return res.status(404).json({ error: 'User not found.' });
    }

    // Remove the user's keys before removing the account.
    // Use a transaction when MongoDB supports it; otherwise use the
    // sequential fallback to avoid requiring a replica set locally.
    const session = await mongoose.startSession();
    let deletedKeyCount = 0;

    try {
      await session.withTransaction(async () => {
        const keyDelete = await Key.deleteMany({ owner: user._id }).session(session);
        deletedKeyCount = keyDelete.deletedCount || 0;
        await User.deleteOne({ _id: user._id }).session(session);
      });
    } catch (transactionError) {
      // Standalone local MongoDB does not support transactions.
      // Only fallback for transaction/replica-set unsupported errors.
      const message = String(transactionError?.message || '');
      const unsupportedTransaction =
        message.includes('Transaction numbers are only allowed') ||
        message.includes('replica set') ||
        message.includes('does not support transactions');

      if (!unsupportedTransaction) {
        throw transactionError;
      }

      const keyDelete = await Key.deleteMany({ owner: user._id });
      deletedKeyCount = keyDelete.deletedCount || 0;

      const userDelete = await User.deleteOne({ _id: user._id });
      if (userDelete.deletedCount !== 1) {
        throw new Error('User account could not be deleted.');
      }
    } finally {
      await session.endSession();
    }

    // Audit logging is best-effort after deletion.
    try {
      await Activity.create({
        actor: req.user._id,
        action: 'user_deleted',
        details: `Deleted user ${user.email}; removed ${deletedKeyCount} owned key(s).`
      });
    } catch (activityError) {
      console.error('User deleted, but activity logging failed:', activityError);
    }

    return res.json({
      success: true,
      message: 'User account and owned keys deleted.',
      deletedKeyCount
    });
  } catch (error) {
    return next(error);
  }
});

router.patch('/users/:id', async (req, res, next) => {
  try {
    const { id } = req.params;

    if (!mongoose.isValidObjectId(id)) {
      return res.status(400).json({ error: 'Invalid user ID.' });
    }

    const hasKeyLimit = Object.prototype.hasOwnProperty.call(req.body, 'keyLimit');
    const hasDisabled = Object.prototype.hasOwnProperty.call(req.body, 'disabled');
    const hasUnlimitedKeyAccess = Object.prototype.hasOwnProperty.call(
      req.body,
      'unlimitedKeyAccess'
    );

    if (!hasKeyLimit && !hasDisabled && !hasUnlimitedKeyAccess) {
      return res.status(400).json({ error: 'No supported user settings were provided.' });
    }

    const user = await User.findById(id);

    // Admin accounts cannot be modified through this endpoint.
    if (!user || user.role === 'admin') {
      return res.status(404).json({ error: 'User not found.' });
    }

    const changes = [];

    if (hasKeyLimit) {
      const limit = Number(req.body.keyLimit);

      if (!Number.isInteger(limit) || limit < 0 || limit > 1000) {
        return res.status(400).json({ error: 'keyLimit must be an integer from 0 to 1000.' });
      }

      if (user.keyLimit !== limit) {
        changes.push(`key limit changed from ${user.keyLimit} to ${limit}`);
        user.keyLimit = limit;
      }
    }

    if (hasDisabled) {
      if (typeof req.body.disabled !== 'boolean') {
        return res.status(400).json({ error: 'disabled must be true or false.' });
      }

      if (user.disabled !== req.body.disabled) {
        changes.push(req.body.disabled ? 'account disabled' : 'account enabled');
        user.disabled = req.body.disabled;
      }
    }

    if (hasUnlimitedKeyAccess) {
      if (typeof req.body.unlimitedKeyAccess !== 'boolean') {
        return res.status(400).json({
          error: 'unlimitedKeyAccess must be true or false.'
        });
      }

      if (user.unlimitedKeyAccess !== req.body.unlimitedKeyAccess) {
        changes.push(
          req.body.unlimitedKeyAccess
            ? 'unlimited key generation enabled'
            : 'unlimited key generation disabled'
        );
        user.unlimitedKeyAccess = req.body.unlimitedKeyAccess;
      }
    }

    if (changes.length === 0) {
      return res.json({ user: safeUser(user) });
    }

    await user.save();

    // Audit logging is best-effort: a logging failure must not report the
    // already-saved user update as failed.
    try {
      await Activity.create({
        actor: req.user._id,
        action: 'user_updated',
        details: `Updated ${user.email}: ${changes.join('; ')}`
      });
    } catch (activityError) {
      console.error('User updated, but activity logging failed:', activityError);
    }

    return res.json({ user: safeUser(user) });
  } catch (error) {
    return next(error);
  }
});

router.get('/activity', async (_req, res, next) => {
  try {
    // Keep only the newest 10 activity records in MongoDB.
    const newestLogs = await Activity.find({})
      .sort({ createdAt: -1, _id: -1 })
      .select('_id')
      .limit(10)
      .lean();

    const keepIds = newestLogs.map((item) => item._id);

    await Activity.deleteMany({
      _id: { $nin: keepIds }
    });

    const items = await Activity.find({})
      .populate('actor', 'name email')
      .sort({ createdAt: -1, _id: -1 })
      .limit(10);

    return res.json({
      activity: items.map((item) => ({
        action: item.action,
        details: item.details,
        createdAt: item.createdAt,
        actor: item.actor
          ? { name: item.actor.name, email: item.actor.email }
          : null
      }))
    });
  } catch (error) {
    return next(error);
  }
});

router.get('/stats', async (_req, res, next) => {
  try {
    const [users, totalKeys, activeKeys, deviceRows, appRegistrations] = await Promise.all([
      User.countDocuments({ role: 'user' }),
      Key.countDocuments(),
      Key.countDocuments({
        status: 'active',
        expiresAt: { $gt: new Date() }
      }),
      Key.distinct('deviceId', {
        deviceId: { $nin: [null, ''] }
      }),
      Key.countDocuments({
        appId: { $nin: [null, ''] }
      })
    ]);

    return res.json({
      users,
      totalKeys,
      activeKeys,
      devices: deviceRows.length,
      appRegistrations
    });
  } catch (error) {
    return next(error);
  }
});

export default router;