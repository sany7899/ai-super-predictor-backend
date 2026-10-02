# AI SUPER PREDICTOR — Online Backend

This backend is designed for the supplied Admin Panel. It moves Sub Panels, keys, locks, deposits and withdrawals to Supabase so data is not limited to one phone/browser.

## Render
- Service type: Web Service
- Build Command: `npm install`
- Start Command: `npm start`
- Add the four variables from `.env.example` in Render Environment Variables.

## Important
Never put `SUPABASE_SERVICE_ROLE_KEY` in the browser, HTML, GitHub frontend, or screenshots. Keep it only in Render environment variables.

## Supabase
Run `schema.sql` in SQL Editor. The existing tables should match the names/columns used by the backend:
- access_keys: id, key, uid, expires, active
- Deposit: id, uid, amount, method, account, status, created_at
- Withdrawal: id, uid, amount, method, account, status, created_at
- Users: existing user table

The backend adds `sub_panels`, `user_locks`, and `admin_settings`.
