import { Router } from 'express';
import Key from '../models/Key.js';
import User from '../models/User.js';
import Activity from '../models/Activity.js';
import { requireAuth } from '../middleware/auth.js';
import { hashKey, makeKey, encryptKey, decryptKey } from '../utils/security.js';

const router = Router();

const DAY_MS = 86400000;
const ttlDays = () => Math.max(
  1,
  Math.min(3650, Number(process.env.DEFAULT_KEY_TTL_DAYS || 8))
);

function presentKey(key) {
  let decryptedKey = null;
  let decryptionError = false;

  try {
    decryptedKey = decryptKey(key.encryptedKey);
  } catch (error) {
    decryptionError = true;
    console.error(
      `Key decryption failed for record ${key._id}:`,
      error.message
    );
  }

  return {
    id: key._id,
    key: decryptedKey,
    keyUnavailable: decryptionError,
    keyHint: key.keyHint,
    type: key.type,
    owner: key.owner,
    deviceId: key.deviceId,
    appId: key.appId,
    status: key.status,
    createdAt: key.createdAt,
    expiresAt: key.expiresAt,
    boundAt: key.boundAt,
    deactivatedAt: key.deactivatedAt,
    revokedAt: key.revokedAt,
    lastVerifiedAt: key.lastVerifiedAt
  };
}

function validateIdentifiers(deviceId, appId) {
  if (!deviceId || !appId) {
    return 'Both Device ID and App ID are required to generate a key.';
  }

  if (deviceId.length > 256 || appId.length > 128) {
    return 'Device ID or App ID is too long.';
  }

  return null;
}

function keyAccessFilter(req) {
  return req.user.role === 'admin'
    ? { _id: req.params.id }
    : { _id: req.params.id, owner: req.user._id };
}

/* -------------------------------------------------------------------------- */
/* List keys                                                                  */
/* -------------------------------------------------------------------------- */

router.get('/', requireAuth, async (req, res, next) => {
  try {
    // Default list is My Keys. Admin may request a selected user's keys
    // for the User Profile page using ownerId; regular users cannot override it.
    const requestedOwnerId = req.query.ownerId;
    const filter = req.user.role === 'admin' && requestedOwnerId
      ? { owner: requestedOwnerId }
      : { owner: req.user._id };

    const keys = await Key.find(filter)
      .populate('owner', 'name email')
      .sort({ createdAt: -1 });

    res.json({
      keys: keys.map((key) => ({
        ...presentKey(key),
        owner: key.owner
          ? {
              id: key.owner._id,
              name: key.owner.name,
              email: key.owner.email
            }
          : null
      }))
    });
  } catch (error) {
    next(error);
  }
});

/* -------------------------------------------------------------------------- */
/* Generate key — Device ID and App ID are mandatory at creation              */
/* -------------------------------------------------------------------------- */

router.post('/generate', requireAuth, async (req, res, next) => {
  try {
    const deviceId = String(req.body.deviceId || '').trim();
    const appId = String(req.body.appId || '').trim();
    const identifierError = validateIdentifiers(deviceId, appId);

    if (identifierError) {
      return res.status(400).json({ error: identifierError });
    }

    const isAdmin = req.user.role === 'admin';
    const type = isAdmin && req.body.type === 'admin' ? 'admin' : 'user';

    let owner = req.user._id;

    if (isAdmin && req.body.ownerId) {
      const target = await User.findById(req.body.ownerId);

      if (!target) {
        return res.status(404).json({ error: 'Target user not found.' });
      }

      owner = target._id;
    }

    if (!isAdmin) {
      const count = await Key.countDocuments({
        owner,
        type: 'user'
      });

      if (count >= req.user.keyLimit) {
        return res.status(403).json({
          error: `Key limit reached (${req.user.keyLimit}). Contact admin.`
        });
      }
    }

    const now = new Date();
    const expiresAt = new Date(now.getTime() + ttlDays() * DAY_MS);

    const plainKey = makeKey();

    const doc = await Key.create({
      keyHash: hashKey(plainKey),
      encryptedKey: encryptKey(plainKey),
      keyHint: plainKey.slice(-4),
      type,
      owner,
      createdBy: req.user._id,
      deviceId,
      appId,
      status: 'active',
      boundAt: now,
      expiresAt
    });

    await Activity.create({
      actor: req.user._id,
      action: 'key_generated',
      details: `${type} key generated for Device ID ${deviceId} and App ID ${appId} (${plainKey.slice(-4)})`,
      keyId: doc._id
    });

    res.status(201).json({ key: presentKey(doc) });
  } catch (error) {
    next(error);
  }
});

/* -------------------------------------------------------------------------- */
/* Verify key — inactive, revoked and expired keys are rejected               */
/* -------------------------------------------------------------------------- */

router.post('/verify', async (req, res, next) => {
  try {
    const plainKey = String(req.body.key || '').trim().toUpperCase();
    const deviceId = String(req.body.deviceId || '').trim();
    const appId = String(req.body.appId || '').trim();

    if (!plainKey || !deviceId || !appId) {
      return res.status(400).json({
        valid: false,
        error: 'key, deviceId and appId are required.'
      });
    }

    if (deviceId.length > 256 || appId.length > 128) {
      return res.status(400).json({
        valid: false,
        error: 'Invalid deviceId or appId.'
      });
    }

    const doc = await Key.findOne({ keyHash: hashKey(plainKey) });

    if (!doc) {
      return res.status(404).json({
        valid: false,
        error: 'Key not found.'
      });
    }

    if (doc.status === 'revoked') {
      return res.status(403).json({
        valid: false,
        error: 'Key has been permanently revoked.'
      });
    }

    if (doc.status === 'inactive') {
      return res.status(403).json({
        valid: false,
        error: 'Key is inactive. Contact the key owner or administrator.'
      });
    }

    if (doc.expiresAt <= new Date()) {
      return res.status(403).json({
        valid: false,
        error: 'Key expired.'
      });
    }

    // New keys are already bound during generation. This fallback supports
    // legacy records that were created before Device ID/App ID became required.
    if (!doc.deviceId && !doc.appId) {
      doc.deviceId = deviceId;
      doc.appId = appId;
      doc.boundAt = new Date();
    } else if (doc.deviceId !== deviceId || doc.appId !== appId) {
      return res.status(403).json({
        valid: false,
        error: 'Key is bound to a different Device ID or App ID.'
      });
    }

    doc.lastVerifiedAt = new Date();
    await doc.save();

    res.json({
      valid: true,
      expiresAt: doc.expiresAt,
      deviceId: doc.deviceId,
      appId: doc.appId
    });
  } catch (error) {
    next(error);
  }
});

/* -------------------------------------------------------------------------- */
/* Deactivate key — reversible; expiry date does not change                   */
/* -------------------------------------------------------------------------- */

router.post('/:id/deactivate', requireAuth, async (req, res, next) => {
  try {
    const key = await Key.findOne(keyAccessFilter(req));

    if (!key) {
      return res.status(404).json({ error: 'Key not found.' });
    }

    if (key.status === 'revoked') {
      return res.status(409).json({
        error: 'A permanently revoked key cannot be deactivated or reactivated.'
      });
    }

    if (key.expiresAt <= new Date()) {
      return res.status(409).json({
        error: 'An expired key cannot be deactivated.'
      });
    }

    if (key.status === 'inactive') {
      return res.json({ ok: true, status: 'inactive', message: 'Key is already inactive.' });
    }

    key.status = 'inactive';
    key.deactivatedAt = new Date();
    await key.save();

    await Activity.create({
      actor: req.user._id,
      action: 'key_deactivated',
      details: `Key ${key.keyHint} deactivated`,
      keyId: key._id
    });

    res.json({ ok: true, status: key.status });
  } catch (error) {
    next(error);
  }
});

/* -------------------------------------------------------------------------- */
/* Activate key — only inactive, unexpired keys can be reactivated            */
/* -------------------------------------------------------------------------- */

router.post('/:id/activate', requireAuth, async (req, res, next) => {
  try {
    const key = await Key.findOne(keyAccessFilter(req));

    if (!key) {
      return res.status(404).json({ error: 'Key not found.' });
    }

    if (key.status === 'revoked') {
      return res.status(409).json({
        error: 'A permanently revoked key cannot be reactivated.'
      });
    }

    if (key.expiresAt <= new Date()) {
      return res.status(409).json({
        error: 'This key has expired and cannot be activated.'
      });
    }

    if (key.status === 'active') {
      return res.json({ ok: true, status: 'active', message: 'Key is already active.' });
    }

    key.status = 'active';
    key.deactivatedAt = null;
    await key.save();

    await Activity.create({
      actor: req.user._id,
      action: 'key_activated',
      details: `Key ${key.keyHint} activated`,
      keyId: key._id
    });

    res.json({ ok: true, status: key.status });
  } catch (error) {
    next(error);
  }
});

/* -------------------------------------------------------------------------- */
/* Revoke key — permanent; cannot be reactivated                              */
/* -------------------------------------------------------------------------- */

router.post('/:id/revoke', requireAuth, async (req, res, next) => {
  try {
    const key = await Key.findOne(keyAccessFilter(req));

    if (!key) {
      return res.status(404).json({ error: 'Key not found.' });
    }

    if (key.status === 'revoked') {
      return res.json({ ok: true, status: 'revoked', message: 'Key is already revoked.' });
    }

    key.status = 'revoked';
    key.revokedAt = new Date();
    key.deactivatedAt = null;
    await key.save();

    await Activity.create({
      actor: req.user._id,
      action: 'key_revoked',
      details: `Key ${key.keyHint} permanently revoked`,
      keyId: key._id
    });

    res.json({ ok: true, status: key.status });
  } catch (error) {
    next(error);
  }
});


/* -------------------------------------------------------------------------- */
/* Delete key — permanent; admin can delete any key, users only their own     */
/* -------------------------------------------------------------------------- */

router.delete('/:id', requireAuth, async (req, res, next) => {
  try {
    const key = await Key.findOne(keyAccessFilter(req));

    if (!key) {
      return res.status(404).json({ error: 'Key not found.' });
    }

    const keyId = key._id;
    const keyHint = key.keyHint;
    const ownerId = key.owner;

    const result = await Key.deleteOne({ _id: keyId });

    if (result.deletedCount !== 1) {
      return res.status(409).json({ error: 'Key could not be deleted. Please refresh and try again.' });
    }

    // Audit logging must not turn a successful deletion into a false 500 response.
    try {
      await Activity.create({
        actor: req.user._id,
        action: 'key_deleted',
        details: `Key ${keyHint} permanently deleted`,
        keyId
      });
    } catch (activityError) {
      console.error('Key deleted, but activity logging failed:', activityError);
    }

    return res.json({
      ok: true,
      deleted: true,
      keyId,
      ownerId
    });
  } catch (error) {
    next(error);
  }
});

/* -------------------------------------------------------------------------- */
/* Key summary                                                                */
/* -------------------------------------------------------------------------- */

router.get('/mine/summary', requireAuth, async (req, res, next) => {
  try {
    // My Keys and its summary should only include keys owned by the
    // currently signed-in account, including when that account is admin.
    const filter = { owner: req.user._id };

    const [total, active, inactive, revoked, expired] = await Promise.all([
      Key.countDocuments(filter),
      Key.countDocuments({
        ...filter,
        status: 'active',
        expiresAt: { $gt: new Date() }
      }),
      Key.countDocuments({ ...filter, status: 'inactive' }),
      Key.countDocuments({ ...filter, status: 'revoked' }),
      Key.countDocuments({
        ...filter,
        status: { $ne: 'revoked' },
        expiresAt: { $lte: new Date() }
      })
    ]);

    res.json({ total, active, inactive, revoked, expired });
  } catch (error) {
    next(error);
  }
});

export default router;