import express from 'express';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { createClient } from '@supabase/supabase-js';

const app = express();
app.use(cors());
app.use(express.json({ limit: '1mb' }));

const PORT = process.env.PORT || 10000;
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const JWT_SECRET = process.env.JWT_SECRET;

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY || !ADMIN_PASSWORD || !JWT_SECRET) {
  console.warn('Missing required environment variables. Set SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, ADMIN_PASSWORD and JWT_SECRET.');
}

const db = SUPABASE_URL && SUPABASE_SERVICE_ROLE_KEY
  ? createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, { auth: { persistSession: false } })
  : null;

const ok = (res, data) => res.json({ ok: true, data });
const fail = (res, code, message) => res.status(code).json({ ok: false, error: message });

function requireConfig(req, res, next) {
  if (!db) return fail(res, 500, 'Server is not configured');
  next();
}
function adminAuth(req, res, next) {
  const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    if (payload.type !== 'admin') throw new Error('bad token');
    req.admin = payload;
    next();
  } catch { return fail(res, 401, 'Admin authentication required'); }
}
function subAuth(req, res, next) {
  const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    if (payload.type !== 'subpanel') throw new Error('bad token');
    req.subpanel = payload;
    next();
  } catch { return fail(res, 401, 'Sub panel login required'); }
}

function panelAuth(permission) {
  return (req, res, next) => {
    const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
    try {
      const p = jwt.verify(token, JWT_SECRET);
      if (p.type === 'admin' || (p.type === 'subpanel' && (!permission || p.permissions?.[permission]))) {
        req.panel = p; return next();
      }
      throw new Error('denied');
    } catch { return fail(res, 401, 'Authentication or permission required'); }
  };
}

function requirePermission(name) {
  return (req, res, next) => {
    if (!req.subpanel?.permissions?.[name]) return fail(res, 403, 'Permission denied');
    next();
  };
}

app.get('/health', (req, res) => ok(res, { service: 'AI SUPER PREDICTOR backend', time: new Date().toISOString() }));

app.post('/api/admin/login', (req, res) => {
  const username = String(req.body?.username || '');
  const password = String(req.body?.password || '');
  if (!ADMIN_PASSWORD) return fail(res, 500, 'Admin password is not configured');
  if (username !== ADMIN_USERNAME || password !== ADMIN_PASSWORD) return fail(res, 401, 'Invalid admin username or password');
  const token = jwt.sign({ type: 'admin', username }, JWT_SECRET, { expiresIn: '12h' });
  ok(res, { token, username });
});

// ---------- Sub Panels ----------
app.get('/api/subpanels', requireConfig, adminAuth, async (req, res) => {
  const { data, error } = await db.from('sub_panels').select('id,name,username,active,permissions,created_at').order('id', { ascending: false });
  if (error) return fail(res, 500, error.message);
  ok(res, data || []);
});

app.post('/api/subpanels', requireConfig, adminAuth, async (req, res) => {
  const { name, username, password, permissions = {} } = req.body || {};
  if (!name || !username || !password) return fail(res, 400, 'Name, username and password are required');
  const password_hash = await bcrypt.hash(password, 12);
  const row = { name: String(name).trim(), username: String(username).trim().toLowerCase(), password_hash, active: true, permissions };
  const { data, error } = await db.from('sub_panels').insert(row).select('id,name,username,active,permissions,created_at').single();
  if (error) return fail(res, error.code === '23505' ? 409 : 500, error.code === '23505' ? 'Username already exists' : error.message);
  ok(res, data);
});

app.patch('/api/subpanels/:id', requireConfig, adminAuth, async (req, res) => {
  const patch = {};
  if (typeof req.body.active === 'boolean') patch.active = req.body.active;
  if (req.body.permissions && typeof req.body.permissions === 'object') patch.permissions = req.body.permissions;
  if (!Object.keys(patch).length) return fail(res, 400, 'Nothing to update');
  const { data, error } = await db.from('sub_panels').update(patch).eq('id', req.params.id).select('id,name,username,active,permissions,created_at').single();
  if (error) return fail(res, 500, error.message);
  ok(res, data);
});

app.delete('/api/subpanels/:id', requireConfig, adminAuth, async (req, res) => {
  const { error } = await db.from('sub_panels').delete().eq('id', req.params.id);
  if (error) return fail(res, 500, error.message);
  ok(res, true);
});

app.post('/api/subpanels/login', requireConfig, async (req, res) => {
  const username = String(req.body?.username || '').trim().toLowerCase();
  const password = String(req.body?.password || '');
  if (!username || !password) return fail(res, 400, 'Username and password are required');
  const { data, error } = await db.from('sub_panels').select('id,name,username,password_hash,active,permissions').eq('username', username).maybeSingle();
  if (error) return fail(res, 500, error.message);
  if (!data || !data.active || !(await bcrypt.compare(password, data.password_hash))) return fail(res, 401, 'Invalid username or password');
  const token = jwt.sign({ type: 'subpanel', id: data.id, username: data.username, permissions: data.permissions || {} }, JWT_SECRET, { expiresIn: '12h' });
  ok(res, { token, subpanel: { id: data.id, name: data.name, username: data.username, permissions: data.permissions || {} } });
});

app.get('/api/me', subAuth, (req, res) => ok(res, req.subpanel));

// ---------- Access Keys ----------
app.get('/api/keys', requireConfig, panelAuth('keys'), async (req, res) => {
  const { data, error } = await db.from('access_keys').select('*').order('id', { ascending: false });
  if (error) return fail(res, 500, error.message);
  ok(res, data || []);
});
app.post('/api/keys', requireConfig, adminAuth, async (req, res) => {
  const { key, uid = '', expires, active = true } = req.body || {};
  if (!key || !expires) return fail(res, 400, 'key and expires are required');
  const { data, error } = await db.from('access_keys').insert({ key, uid, expires, active }).select('*').single();
  if (error) return fail(res, error.code === '23505' ? 409 : 500, error.message);
  ok(res, data);
});
app.patch('/api/keys/:id', requireConfig, adminAuth, async (req, res) => {
  const { data, error } = await db.from('access_keys').update({ active: !!req.body.active }).eq('id', req.params.id).select('*').single();
  if (error) return fail(res, 500, error.message);
  ok(res, data);
});

// ---------- Users / Locks ----------
app.get('/api/locks', requireConfig, panelAuth('users'), async (req, res) => {
  const { data, error } = await db.from('user_locks').select('*').order('id', { ascending: false });
  if (error) return fail(res, 500, error.message);
  ok(res, data || []);
});
app.post('/api/locks', requireConfig, panelAuth('users'), async (req, res) => {
  const { uid, reason } = req.body || {};
  if (!uid || !reason) return fail(res, 400, 'UID and reason are required');
  const { data, error } = await db.from('user_locks').insert({ uid, reason }).select('*').single();
  if (error) return fail(res, 500, error.message);
  ok(res, data);
});
app.delete('/api/locks/:id', requireConfig, panelAuth('users'), async (req, res) => {
  const { error } = await db.from('user_locks').delete().eq('id', req.params.id);
  if (error) return fail(res, 500, error.message);
  ok(res, true);
});

// ---------- Deposits / Withdrawals ----------
app.get('/api/deposits', requireConfig, panelAuth('deposit'), async (req, res) => {
  const { data, error } = await db.from('Deposit').select('*').order('id', { ascending: false });
  if (error) return fail(res, 500, error.message);
  ok(res, data || []);
});
app.patch('/api/deposits/:id', requireConfig, panelAuth('deposit'), async (req, res) => {
  const status = String(req.body?.status || '');
  if (!['Approved', 'Rejected', 'approved', 'rejected'].includes(status)) return fail(res, 400, 'Invalid status');
  const { data, error } = await db.from('Deposit').update({ status: status[0].toUpperCase() + status.slice(1).toLowerCase() }).eq('id', req.params.id).select('*').single();
  if (error) return fail(res, 500, error.message);
  ok(res, data);
});
app.get('/api/withdrawals', requireConfig, panelAuth('withdraw'), async (req, res) => {
  const { data, error } = await db.from('Withdrawal').select('*').order('id', { ascending: false });
  if (error) return fail(res, 500, error.message);
  ok(res, data || []);
});
app.patch('/api/withdrawals/:id', requireConfig, panelAuth('withdraw'), async (req, res) => {
  const status = String(req.body?.status || '');
  if (!['Approved', 'Rejected', 'approved', 'rejected'].includes(status)) return fail(res, 400, 'Invalid status');
  const { data, error } = await db.from('Withdrawal').update({ status: status[0].toUpperCase() + status.slice(1).toLowerCase() }).eq('id', req.params.id).select('*').single();
  if (error) return fail(res, 500, error.message);
  ok(res, data);
});

// ---------- Admin settings (support + DP list) ----------
app.get('/api/settings', requireConfig, adminAuth, async (req, res) => {
  const { data, error } = await db.from('admin_settings').select('*').order('key');
  if (error) return fail(res, 500, error.message);
  ok(res, Object.fromEntries((data || []).map(x => [x.key, x.value])));
});
app.put('/api/settings/:key', requireConfig, adminAuth, async (req, res) => {
  const { data, error } = await db.from('admin_settings').upsert({ key: req.params.key, value: req.body?.value ?? null }).select('*').single();
  if (error) return fail(res, 500, error.message);
  ok(res, data);
});

app.use((req, res) => fail(res, 404, 'Route not found'));
app.listen(PORT, () => console.log(`AI SUPER PREDICTOR backend listening on ${PORT}`));
