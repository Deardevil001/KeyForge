import mongoose from 'mongoose';
import User from '../models/User.js';

export async function requireAuth(req, res, next) {
  try {
    const userId = req.session?.userId;

    if (!userId) {
      return res.status(401).json({ error: 'Login required.' });
    }

    // Reject malformed session IDs instead of allowing a Mongoose CastError
    // to become a server error.
    if (!mongoose.isValidObjectId(userId)) {
      await new Promise((resolve) => {
        if (!req.session) return resolve();
        req.session.destroy(() => resolve());
      });

      return res.status(401).json({ error: 'Session is invalid. Please sign in again.' });
    }

    const user = await User.findById(userId);

    if (!user || user.disabled) {
      await new Promise((resolve) => {
        if (!req.session) return resolve();
        req.session.destroy(() => resolve());
      });

      return res.status(401).json({ error: 'Account unavailable.' });
    }

    // Invalidate sessions created before the user's password was reset.
    const sessionVersion = req.session.sessionVersion;
    if (
      !Number.isInteger(sessionVersion) ||
      sessionVersion !== user.sessionVersion
    ) {
      await new Promise((resolve) => {
        if (!req.session) return resolve();
        req.session.destroy(() => resolve());
      });

      return res.status(401).json({ error: 'Session expired. Please sign in again.' });
    }

    req.user = user;
    return next();
  } catch (error) {
    return next(error);
  }
}

export function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required.' });
  }

  return next();
}