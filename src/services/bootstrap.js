
import bcrypt from 'bcryptjs';
import User from '../models/User.js';

export async function ensureAdmin() {
  const email = process.env.ADMIN_EMAIL?.trim().toLowerCase();
  const password = process.env.ADMIN_PASSWORD;
  const name = process.env.ADMIN_NAME?.trim() || 'Administrator';

  if (!email || !password) {
    console.warn(
      'ADMIN_EMAIL / ADMIN_PASSWORD not set; no admin bootstrap account created.'
    );
    return;
  }

  if (password.length < 12) {
    throw new Error('ADMIN_PASSWORD must be at least 12 characters long.');
  }

  if (Buffer.byteLength(password, 'utf8') > 72) {
    throw new Error('ADMIN_PASSWORD must not exceed 72 UTF-8 bytes.');
  }

  const existing = await User.findOne({ email });

  const passwordHash = await bcrypt.hash(password, 12);

  if (existing) {
    if (existing.role !== 'admin') {
      throw new Error(
        `ADMIN_EMAIL belongs to a non-admin account (${email}).`
      );
    }

    // Reset existing admin password only when explicitly enabled.
    if (process.env.ADMIN_RESET_PASSWORD === 'true') {
      existing.passwordHash = passwordHash;
      existing.name = name;

      await existing.save();

      console.log(`Admin password successfully reset: ${email}`);
    } else {
      console.log(`Existing admin account found: ${email}`);
    }

    return;
  }

  await User.create({
    name,
    email,
    passwordHash,
    role: 'admin',
    keyLimit: 1000
  });

  console.log(`Initial admin account created: ${email}`);
}
