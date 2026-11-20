import { Router } from 'express';
import { rateLimit } from 'express-rate-limit';
import crypto from 'node:crypto';

import AccountVerification from '../models/AccountVerification.js';
import { requireAuth } from '../middleware/auth.js';

const router = Router();

const verifyLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    valid: false,
    error: 'Too many verification attempts. Try again later.'
  }
});

function getEncryptionKey() {
  const encoded = process.env.ACCOUNT_VERIFICATION_ENCRYPTION_KEY || '';
  let key;

  try {
    key = Buffer.from(encoded, 'base64');
  } catch {
    throw new Error('ACCOUNT_VERIFICATION_ENCRYPTION_KEY must be a base64-encoded 32-byte key.');
  }

  if (key.length !== 32) {
    throw new Error('ACCOUNT_VERIFICATION_ENCRYPTION_KEY must decode to exactly 32 bytes.');
  }

  return key;
}

function encryptSecret(secret) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', getEncryptionKey(), iv);
  const ciphertext = Buffer.concat([
    cipher.update(secret, 'utf8'),
    cipher.final()
  ]);
  const tag = cipher.getAuthTag();

  // Versioned format: v1:IV:TAG:CIPHERTEXT (base64url encoded parts).
  return [
    'v1',
    iv.toString('base64url'),
    tag.toString('base64url'),
    ciphertext.toString('base64url')
  ].join(':');
}

function decryptSecret(encryptedSecret) {
  const [version, ivPart, tagPart, ciphertextPart] =
    String(encryptedSecret || '').split(':');

  if (version !== 'v1' || !ivPart || !tagPart || !ciphertextPart) {
    throw new Error('Stored account verification string has an invalid encrypted format.');
  }

  const decipher = crypto.createDecipheriv(
    'aes-256-gcm',
    getEncryptionKey(),
    Buffer.from(ivPart, 'base64url')
  );

  decipher.setAuthTag(Buffer.from(tagPart, 'base64url'));

  return Buffer.concat([
    decipher.update(Buffer.from(ciphertextPart, 'base64url')),
    decipher.final()
  ]).toString('utf8');
}

function hashSecret(secret) {
  return crypto.createHash('sha256').update(secret).digest('hex');
}

function createSecret() {
  return crypto.randomBytes(32).toString('base64url');
}

async function createRecord(owner, generation = 1) {
  const secret = createSecret();

  const record = await AccountVerification.create({
    owner,
    secretHash: hashSecret(secret),
    encryptedSecret: encryptSecret(secret),
    status: 'active',
    generation,
    revokedAt: null,
    lastVerifiedAt: null
  });

  return { record, secret };
}

/*
 * Authenticated account UI:
 * GET /api/account-verification/current
 *
 * Returns the existing active string. If the account has no record yet,
 * it creates one on first visit. A revoked record is not silently reactivated.
 */
router.get('/current', requireAuth, async (req, res, next) => {
  try {
    const owner = req.user._id;
    let record = await AccountVerification.findOne({ owner });

    if (!record) {
      try {
        const created = await createRecord(owner);
        record = created.record;
        return res.json({
          ok: true,
          status: record.status,
          generation: record.generation,
          verificationString: created.secret
        });
      } catch (error) {
        // Handle simultaneous first-load requests: unique owner index allows
        // only one record; read the record created by the other request.
        if (error?.code !== 11000) throw error;
        record = await AccountVerification.findOne({ owner });
      }
    }

    if (!record) {
      return res.status(500).json({
        error: 'Could not load account verification string.'
      });
    }

    return res.json({
      ok: true,
      status: record.status,
      generation: record.generation,
      verificationString: decryptSecret(record.encryptedSecret)
    });
  } catch (error) {
    next(error);
  }
});

/*
 * Authenticated account UI:
 * POST /api/account-verification/rotate
 * Body: {}
 * Generates a new string and invalidates the previous string.
 */
router.post('/rotate', requireAuth, async (req, res, next) => {
  try {
    const owner = req.user._id;
    const secret = createSecret();
    const secretHash = hashSecret(secret);
    const encryptedSecret = encryptSecret(secret);

    const record = await AccountVerification.findOneAndUpdate(
      { owner },
      {
        $set: {
          secretHash,
          encryptedSecret,
          status: 'active',
          revokedAt: null,
          lastVerifiedAt: null
        },
        $inc: { generation: 1 },
        $setOnInsert: { owner }
      },
      {
        new: true,
        upsert: true,
        runValidators: true,
        setDefaultsOnInsert: true
      }
    );

    return res.json({
      ok: true,
      status: record.status,
      generation: record.generation,
      verificationString: secret
    });
  } catch (error) {
    next(error);
  }
});

/*
 * Authenticated account UI:
 * POST /api/account-verification/revoke
 * Body: {}
 */
router.post('/revoke', requireAuth, async (req, res, next) => {
  try {
    const record = await AccountVerification.findOne({
      owner: req.user._id
    });

    if (!record) {
      return res.status(404).json({
        error: 'Account verification string not found.'
      });
    }

    if (record.status !== 'revoked') {
      record.status = 'revoked';
      record.revokedAt = new Date();
      await record.save();
    }

    return res.json({
      ok: true,
      status: 'revoked'
    });
  } catch (error) {
    next(error);
  }
});

/*
 * Verify account string only:
 * POST /api/account-verification/launch-check
 * Body: { "accountVerificationString": "..." }
 */
router.post('/launch-check', verifyLimiter, async (req, res, next) => {
  try {
    const secret = String(
      req.body?.accountVerificationString || ''
    ).trim();

    if (!secret) {
      return res.status(400).json({
        valid: false,
        error: 'accountVerificationString is required.'
      });
    }

    if (secret.length > 256) {
      return res.status(400).json({
        valid: false,
        error: 'Invalid verification data.'
      });
    }

    const verification = await AccountVerification.findOne({
      secretHash: hashSecret(secret),
      status: 'active'
    }).select('_id generation');

    if (!verification) {
      return res.status(403).json({
        valid: false,
        error: 'Account verification failed.'
      });
    }

    await AccountVerification.updateOne(
      { _id: verification._id },
      { $set: { lastVerifiedAt: new Date() } }
    );

    return res.json({
      valid: true,
      generation: verification.generation
    });
  } catch (error) {
    next(error);
  }
});

export default router;