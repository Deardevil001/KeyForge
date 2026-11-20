import { Router } from 'express';
import bcrypt from 'bcryptjs';
import mongoose from 'mongoose';
import crypto from 'node:crypto';
import nodemailer from 'nodemailer';
import User from '../models/User.js';
import Activity from '../models/Activity.js';
import { requireAuth } from '../middleware/auth.js';
import { safeUser } from '../utils/security.js';

const router = Router();

const RESET_TTL_MS = 15 * 60 * 1000;
const GENERIC_RESET_MESSAGE =
  'If an account exists for that email, a password reset link has been sent.';

const logActivity = async (entry) => {
  try {
    await Activity.create(entry);
  } catch (error) {
    console.error('Activity logging failed:', error);
  }
};

const isDuplicateEmailError = (error) =>
  error?.code === 11000 && (
    error?.keyPattern?.email ||
    String(error?.message || '').includes('email')
  );

/*
 * Reset tokens are stored separately from users. Only the SHA-256 hash is
 * stored; the raw token is sent by email and is never saved in MongoDB.
 */
const passwordResetSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    unique: true
  },
  tokenHash: {
    type: String,
    required: true,
    unique: true
  },
  expiresAt: {
    type: Date,
    required: true,
    index: { expires: 0 }
  }
}, { timestamps: true });

const PasswordReset = mongoose.models.PasswordReset ||
  mongoose.model('PasswordReset', passwordResetSchema);

let mailTransport;

function getMailTransport() {
  if (mailTransport) return mailTransport;

  const { SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS } = process.env;

  if (!SMTP_HOST || !SMTP_PORT || !SMTP_USER || !SMTP_PASS) {
    throw new Error('SMTP configuration is incomplete.');
  }

  mailTransport = nodemailer.createTransport({
    host: SMTP_HOST,
    port: Number(SMTP_PORT),
    secure: Number(SMTP_PORT) === 465,
    auth: {
      user: SMTP_USER,
      pass: SMTP_PASS
    }
  });

  return mailTransport;
}

function getPublicBaseUrl() {
  const value = process.env.APP_BASE_URL;

  if (!value) {
    throw new Error('APP_BASE_URL is not configured.');
  }

  const url = new URL(value);

  if (
    !['http:', 'https:'].includes(url.protocol) ||
    (process.env.NODE_ENV === 'production' && url.protocol !== 'https:')
  ) {
    throw new Error('APP_BASE_URL must use HTTPS in production.');
  }

  return url.origin;
}

function validPassword(password) {
  return typeof password === 'string' &&
    password.length >= 10 &&
    password.length <= 128 &&
    Buffer.byteLength(password, 'utf8') <= 72;
}

function passwordError() {
  return 'Password must be 10–128 characters and no more than 72 UTF-8 bytes.';
}

router.post('/register', async (req, res, next) => {
  try {
    const name = typeof req.body?.name === 'string' ? req.body.name.trim() : '';
    const email = typeof req.body?.email === 'string'
      ? req.body.email.trim().toLowerCase()
      : '';
    const password = typeof req.body?.password === 'string'
      ? req.body.password
      : '';

    if (name.length < 2 || name.length > 80) {
      return res.status(400).json({ error: 'Name must be 2–80 characters.' });
    }

    if (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ error: 'Enter a valid email.' });
    }

    if (!validPassword(password)) {
      return res.status(400).json({ error: passwordError() });
    }

    const defaultKeyLimit = Number(process.env.DEFAULT_USER_KEY_LIMIT ?? 25);

    if (!Number.isInteger(defaultKeyLimit) || defaultKeyLimit < 0 || defaultKeyLimit > 1000) {
      return res.status(500).json({
        error: 'DEFAULT_USER_KEY_LIMIT must be an integer from 0 to 1000.'
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    let user;
    try {
      user = await User.create({
        name,
        email,
        passwordHash,
        keyLimit: defaultKeyLimit
      });
    } catch (error) {
      if (isDuplicateEmailError(error)) {
        return res.status(409).json({ error: 'Email already registered.' });
      }
      throw error;
    }

    await new Promise((resolve, reject) => {
      req.session.regenerate((error) => error ? reject(error) : resolve());
    });

    req.session.userId = String(user._id);
    req.session.sessionVersion = Number(user.sessionVersion || 0);

    await logActivity({
      actor: user._id,
      action: 'account_created',
      details: 'Created an account'
    });

    return res.status(201).json({ user: safeUser(user) });
  } catch (error) {
    return next(error);
  }
});

router.post('/login', async (req, res, next) => {
  try {
    const email = typeof req.body?.email === 'string'
      ? req.body.email.trim().toLowerCase()
      : '';
    const password = typeof req.body?.password === 'string'
      ? req.body.password
      : '';

    if (!email || !password || Buffer.byteLength(password, 'utf8') > 72) {
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    const user = await User.findOne({ email });

    if (!user || user.disabled || !(await bcrypt.compare(password, user.passwordHash))) {
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    await new Promise((resolve, reject) => {
      req.session.regenerate((error) => error ? reject(error) : resolve());
    });

    req.session.userId = String(user._id);
    req.session.sessionVersion = Number(user.sessionVersion || 0);

    await logActivity({
      actor: user._id,
      action: 'login',
      details: 'Signed in'
    });

    return res.json({ user: safeUser(user) });
  } catch (error) {
    return next(error);
  }
});

/*
 * Public endpoint. It always returns the same message so callers cannot
 * discover whether an email address is registered.
 */
router.post('/forgot-password', async (req, res, next) => {
  try {
    const email = typeof req.body?.email === 'string'
      ? req.body.email.trim().toLowerCase()
      : '';

    if (!email || email.length > 254 ||
        !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.json({ message: GENERIC_RESET_MESSAGE });
    }

    const user = await User.findOne({ email, disabled: { $ne: true } });

    if (!user) {
      return res.json({ message: GENERIC_RESET_MESSAGE });
    }

    const rawToken = crypto.randomBytes(32).toString('hex');
    const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');
    const expiresAt = new Date(Date.now() + RESET_TTL_MS);

    await PasswordReset.findOneAndUpdate(
      { userId: user._id },
      { $set: { tokenHash, expiresAt } },
      { upsert: true, new: true, setDefaultsOnInsert: true }
    );

    const resetUrl = new URL('/reset-password.html', getPublicBaseUrl());
    resetUrl.searchParams.set('token', rawToken);

    try {
      await getMailTransport().sendMail({
        from: process.env.SMTP_FROM || process.env.SMTP_USER,
        to: user.email,
        subject: 'KeyForge password reset',
        text: [
          `Hello ${user.name},`,
          '',
          'A password reset was requested for your KeyForge account.',
          `Use this link within 15 minutes: ${resetUrl.toString()}`,
          '',
          'If you did not request this, you can ignore this email.'
        ].join('\n'),
        html: `
          <p>Hello ${escapeHtml(user.name)},</p>
          <p>A password reset was requested for your KeyForge account.</p>
          <p><a href="${escapeHtml(resetUrl.toString())}">Reset password</a></p>
          <p>This link expires in 15 minutes and can only be used once.</p>
          <p>If you did not request this, ignore this email.</p>
        `
      });
    } catch (mailError) {
      await PasswordReset.deleteOne({ userId: user._id, tokenHash });
      throw mailError;
    }

    return res.json({ message: GENERIC_RESET_MESSAGE });
  } catch (error) {
    return next(error);
  }
});

/*
 * A reset token is consumed atomically. Password changes increment
 * sessionVersion; the auth middleware will be updated next to reject old
 * sessions whose stored version no longer matches.
 */
router.post('/reset-password', async (req, res, next) => {
  try {
    const token = typeof req.body?.token === 'string' ? req.body.token : '';
    const password = typeof req.body?.password === 'string'
      ? req.body.password
      : '';

    if (!/^[a-f0-9]{64}$/i.test(token)) {
      return res.status(400).json({ error: 'Reset link is invalid or expired.' });
    }

    if (!validPassword(password)) {
      return res.status(400).json({ error: passwordError() });
    }

    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');

    const resetRecord = await PasswordReset.findOneAndDelete({
      tokenHash,
      expiresAt: { $gt: new Date() }
    });

    if (!resetRecord) {
      return res.status(400).json({ error: 'Reset link is invalid or expired.' });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const user = await User.findOneAndUpdate(
      { _id: resetRecord.userId, disabled: { $ne: true } },
      {
        $set: { passwordHash },
        $inc: { sessionVersion: 1 }
      },
      { new: true, runValidators: true }
    );

    if (!user) {
      return res.status(400).json({ error: 'Reset link is invalid or expired.' });
    }

    await PasswordReset.deleteMany({ userId: user._id });

    await logActivity({
      actor: user._id,
      action: 'password_reset',
      details: 'Password reset using email link'
    });

    return res.json({
      message: 'Password updated. Sign in again with your new password.'
    });
  } catch (error) {
    return next(error);
  }
});

router.post('/logout', (req, res, next) => {
  if (!req.session) {
    res.clearCookie('keyforge.sid', {
      httpOnly: true,
      sameSite: 'lax',
      secure: process.env.NODE_ENV === 'production'
    });
    return res.json({ ok: true });
  }

  req.session.destroy((error) => {
    if (error) return next(error);

    res.clearCookie('keyforge.sid', {
      httpOnly: true,
      sameSite: 'lax',
      secure: process.env.NODE_ENV === 'production'
    });

    return res.json({ ok: true });
  });
});

router.get('/me', requireAuth, (req, res) => {
  return res.json({ user: safeUser(req.user) });
});

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (character) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  })[character]);
}

export default router;