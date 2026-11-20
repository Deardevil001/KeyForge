import crypto from 'node:crypto';

function getEncryptionSecret() {
  const value = process.env.KEY_ENCRYPTION_SECRET;

  if (typeof value !== 'string' || !/^[a-fA-F0-9]{64}$/.test(value)) {
    throw new Error(
      'KEY_ENCRYPTION_SECRET must be exactly 64 hexadecimal characters (32 bytes).'
    );
  }

  return Buffer.from(value, 'hex');
}

export function hashKey(value) {
  if (typeof value !== 'string' || value.length === 0) {
    throw new TypeError('Key value must be a non-empty string.');
  }

  return crypto.createHash('sha256').update(value, 'utf8').digest('hex');
}

export function makeKey() {
  const part = () => crypto.randomBytes(3).toString('hex').toUpperCase();
  return `KF-${part()}-${part()}-${part()}-${part()}`;
}

export function encryptKey(value) {
  if (typeof value !== 'string' || value.length === 0) {
    throw new TypeError('Key value must be a non-empty string.');
  }

  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', getEncryptionSecret(), iv);
  const encrypted = Buffer.concat([
    cipher.update(value, 'utf8'),
    cipher.final()
  ]);

  return [
    iv.toString('hex'),
    cipher.getAuthTag().toString('hex'),
    encrypted.toString('hex')
  ].join(':');
}

export function decryptKey(value) {
  if (typeof value !== 'string') {
    throw new TypeError('Encrypted key must be a string.');
  }

  const parts = value.split(':');

  if (parts.length !== 3) {
    throw new Error('Invalid encrypted key format.');
  }

  const [ivHex, tagHex, dataHex] = parts;
  const isHex = (input) => input.length > 0 && input.length % 2 === 0 && /^[a-fA-F0-9]+$/.test(input);

  if (
    !/^[a-fA-F0-9]{24}$/.test(ivHex) ||
    !/^[a-fA-F0-9]{32}$/.test(tagHex) ||
    !isHex(dataHex)
  ) {
    throw new Error('Invalid encrypted key data.');
  }

  const decipher = crypto.createDecipheriv(
    'aes-256-gcm',
    getEncryptionSecret(),
    Buffer.from(ivHex, 'hex')
  );

  decipher.setAuthTag(Buffer.from(tagHex, 'hex'));

  // GCM authentication is checked by final(); tampered ciphertext throws.
  return Buffer.concat([
    decipher.update(Buffer.from(dataHex, 'hex')),
    decipher.final()
  ]).toString('utf8');
}

export function safeUser(user) {
  if (!user) {
    throw new TypeError('A user document is required.');
  }

  return {
    id: String(user._id),
    name: user.name,
    email: user.email,
    role: user.role,
    keyLimit: user.keyLimit,
    disabled: user.disabled,
    unlimitedKeyAccess: user.unlimitedKeyAccess === true
  };
}