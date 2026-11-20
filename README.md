# KeyForge

KeyForge is an Express/MongoDB key-management portal configured for Netlify Functions.

## Netlify deployment

1. Push this project to a Git repository.
2. Import the repository into Netlify.
3. Netlify build settings are defined in `netlify.toml` (`public` publish directory and `netlify/functions` functions directory).
4. Add every required value from `.env.example` in **Site configuration → Environment variables**.
5. Deploy the site.
6. Test `https://YOUR-SITE.netlify.app/api/health`.

The health endpoint reports database connectivity only after the database middleware has connected successfully.

## Required environment variables

- `MONGODB_URI`
- `SESSION_SECRET` (at least 32 characters)
- `KEY_ENCRYPTION_SECRET` (exactly 64 hexadecimal characters)
- `ACCOUNT_VERIFICATION_ENCRYPTION_KEY` (base64 encoding of exactly 32 random bytes)
- `ADMIN_EMAIL`
- `ADMIN_PASSWORD` (at least 12 characters; maximum 72 UTF-8 bytes)
- `ADMIN_NAME`
- `APP_BASE_URL`
- `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `SMTP_FROM` for password reset email

Generate encryption secrets locally:

```bash
node -e "console.log(require('node:crypto').randomBytes(32).toString('hex'))"
node -e "console.log(require('node:crypto').randomBytes(32).toString('base64'))"
```

Keep encryption secrets stable. Replacing them without migrating encrypted database values makes existing encrypted keys or verification strings unreadable.

## Local development

```bash
npm install
cp .env.example .env
# Edit .env with real values
npm run dev
```

## Important deployment notes

- Do not upload `.env` or commit credentials.
- Netlify Functions are request-driven; this is not a continuously running Express process.
- The application uses MongoDB for data and persistent sessions.
- Key expiry is calculated by the server using `DEFAULT_KEY_TTL_DAYS` (default 8 days); the browser cannot extend it.
- Keep the `KEY_ENCRYPTION_SECRET` and `ACCOUNT_VERIFICATION_ENCRYPTION_KEY` values from any existing deployment if you need to read existing encrypted records.
