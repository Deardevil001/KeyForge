
import 'dotenv/config';

import express from 'express';
import mongoose from 'mongoose';
import session from 'express-session';
import MongoStore from 'connect-mongo';
import helmet from 'helmet';
import path from 'node:path';
import { rateLimit } from 'express-rate-limit';

import authRoutes from './src/routes/auth.js';
import keyRoutes from './src/routes/keys.js';
import accountVerificationRoutes from './src/routes/accountVerification.js';
import adminRoutes from './src/routes/admin.js';
import { ensureAdmin } from './src/services/bootstrap.js';

const app = express();

const publicDirectory = path.resolve('public');

// Required environment variables.
for (const name of [
  'MONGODB_URI',
  'SESSION_SECRET',
  'KEY_ENCRYPTION_SECRET'
]) {
  if (!process.env[name]) {
    throw new Error(`Missing environment variable: ${name}`);
  }
}

if (process.env.SESSION_SECRET.length < 32) {
  throw new Error('SESSION_SECRET must be at least 32 characters.');
}

if (!/^[a-fA-F0-9]{64}$/.test(process.env.KEY_ENCRYPTION_SECRET)) {
  throw new Error(
    'KEY_ENCRYPTION_SECRET must be 64 hexadecimal characters.'
  );
}

// Reuse MongoDB connection per serverless instance.
let databasePromise;

async function connectDatabase() {
  if (mongoose.connection.readyState === 1) {
    return;
  }

  if (!databasePromise) {
    databasePromise = (async () => {
      await mongoose.connect(process.env.MONGODB_URI, {
        serverSelectionTimeoutMS: 10000,
        maxPoolSize: 10
      });

      console.log('MongoDB connected successfully');

      await ensureAdmin();

      console.log('Admin initialization completed');
    })().catch((error) => {
      databasePromise = null;
      throw error;
    });
  }

  await databasePromise;
}

// Ensure database is ready before every request.
app.use(async (_req, _res, next) => {
  try {
    await connectDatabase();
    next();
  } catch (error) {
    console.error('Database initialization failed:', error);
    next(error);
  }
});

app.disable('x-powered-by');
app.set('trust proxy', 1);

app.use(helmet({
  contentSecurityPolicy: false
}));

app.use(express.json({
  limit: '20kb'
}));

app.use(express.urlencoded({
  extended: false,
  limit: '20kb'
}));

// Persistent MongoDB sessions.
const SESSION_TTL_SECONDS = 7 * 24 * 60 * 60;

const sessionStore = MongoStore.create({
  mongoUrl: process.env.MONGODB_URI,
  collectionName: 'sessions',
  ttl: SESSION_TTL_SECONDS,
  touchAfter: 60 * 60,
  autoRemove: 'native'
});

sessionStore.on('error', (error) => {
  console.error('MongoDB session store error:', error);
});

app.use(session({
  name: 'keyforge.sid',
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  rolling: false,
  store: sessionStore,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: SESSION_TTL_SECONDS * 1000
  }
}));

// Authentication rate limiting.
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'Too many authentication attempts. Try again later.'
  }
});

app.use('/api/auth/login', authLimiter);
app.use('/api/auth/register', authLimiter);

// Health endpoint.
app.get('/api/health', (_req, res) => {
  res.json({
    ok: true,
    database: mongoose.connection.readyState === 1
      ? 'connected'
      : 'disconnected'
  });
});

// Serve frontend files.
app.use(express.static(publicDirectory));

app.get('/', (_req, res) => {
  res.sendFile(path.join(publicDirectory, 'index.html'));
});

// API routes.
app.use('/api/auth', authRoutes);
app.use('/api/keys', keyRoutes);
app.use('/api/account-verification', accountVerificationRoutes);
app.use('/api/admin', adminRoutes);

// Unknown API routes.
app.use('/api', (_req, res) => {
  res.status(404).json({
    error: 'API endpoint not found.'
  });
});

// Error handler.
app.use((err, _req, res, _next) => {
  console.error('Application error:', err);

  if (res.headersSent) return;

  const status =
    Number.isInteger(err.status) &&
    err.status >= 400 &&
    err.status < 600
      ? err.status
      : 500;

  res.status(status).json({
    error: status >= 500
      ? 'Internal server error.'
      : (err.expose ? err.message : 'Request failed.')
  });
});

// Export Express app for Netlify Functions.
export default app;

// Local development support.
if (!process.env.NETLIFY && !process.env.VERCEL) {
  const PORT = process.env.PORT || 3000;

  connectDatabase()
    .then(() => {
      app.listen(PORT, () => {
        console.log(`KeyForge running at http://localhost:${PORT}`);
      });
    })
    .catch((error) => {
      console.error('Server startup failed:', error);
      process.exit(1);
    });
}
