// server.js
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const cors = require('cors');
const path = require('path');
const jwt = require('jsonwebtoken');
const fs = require('fs');

const BACKUP_JSON = process.env.BACKUP_JSON_PATH
  ? process.env.BACKUP_JSON_PATH
  : (fs.existsSync(path.join(__dirname, 'db_backup.json')) ? path.join(__dirname, 'db_backup.json')
     : (fs.existsSync(path.join(process.cwd(), 'db_backup.json')) ? path.join(process.cwd(), 'db_backup.json')
        : (fs.existsSync('/mnt/data/db_backup.json') ? '/mnt/data/db_backup.json' : null)));

const FORCE_RESTORE = String(process.env.FORCE_RESTORE || 'false').toLowerCase() === 'true';

function tableExists(db, table) {
  return new Promise((resolve, reject) => {
    db.get(`SELECT name FROM sqlite_master WHERE type='table' AND name=?`, [table], (err, row) => {
      if (err) return reject(err);
      resolve(!!row);
    });
  });
}

function getTableColumns(db, table) {
  return new Promise((resolve, reject) => {
    db.all(`PRAGMA table_info(${table})`, [], (err, rows) => {
      if (err) return reject(err);
      resolve(rows.map(r => r.name));
    });
  });
}

async function maybeRestoreFromBackup(db, dbFilePath) {
  try {
    const dbExists = fs.existsSync(dbFilePath) && fs.statSync(dbFilePath).size > 0;
    if (!BACKUP_JSON) {
      console.log('🔍 No db_backup.json found — skipping restore.');
      return;
    }
    if (dbExists && !FORCE_RESTORE) {
      console.log('🔒 DB exists & FORCE_RESTORE=false — skipping JSON restore.');
      return;
    }
    const raw = fs.readFileSync(BACKUP_JSON, 'utf8');
    const parsed = JSON.parse(raw);
    const tables = Object.keys(parsed).filter(k => Array.isArray(parsed[k]));

    await new Promise((resolve, reject) => db.run('BEGIN TRANSACTION;', err => err ? reject(err) : resolve()));
    for (const t of tables) {
      const rows = parsed[t];
      if (!rows || rows.length === 0) continue;

      const exists = await tableExists(db, t);
      if (!exists) {
        console.warn(`⚠️ Table "${t}" not found; skipping.`);
        continue;
      }
      const cols = await getTableColumns(db, t);
      const sampleCols = Object.keys(rows[0]).filter(c => cols.includes(c));
      if (sampleCols.length === 0) {
        console.warn(`⚠️ Table "${t}" has no overlapping columns; skipping.`);
        continue;
      }
      const placeholders = sampleCols.map(() => '?').join(',');
      const colList = sampleCols.map(c => `"${c}"`).join(',');
      const sql = `INSERT OR REPLACE INTO ${t} (${colList}) VALUES (${placeholders})`;

      await new Promise((resolve, reject) => {
        const stmt = db.prepare(sql, err => { if (err) reject(err); });
        let failed = false;
        for (const r of rows) {
          const vals = sampleCols.map(c => r[c] === undefined ? null : r[c]);
          stmt.run(vals, e => { if (e) { failed = true; console.error(`❌ Insert failed on table ${t}:`, e.message); } });
        }
        stmt.finalize(e => {
          if (e || failed) reject(e || new Error('Some inserts failed'));
          else resolve();
        });
      });
      console.log(`✅ Restored ${rows.length} rows into "${t}"`);
    }
    await new Promise((resolve, reject) => db.run('COMMIT;', err => err ? reject(err) : resolve()));
  } catch (e) {
    console.error('❌ Restore failed:', e);
    try { await new Promise((resolve, reject) => db.run('ROLLBACK;', err => err ? reject(err) : resolve())); } catch {}
  }
}
// ======== End auto-restore snippet ========



const app = express();

// ---- Config ----
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'supersecretkey';
const dbPath = process.env.DATABASE_PATH || '/mnt/data/dolphin.db';
const staticDir = process.env.STATIC_DIR || path.join(__dirname, '../frontend');

// ---- Ensure DB directory exists ----
const dirPath = path.dirname(dbPath);
if (!fs.existsSync(dirPath)) {
  fs.mkdirSync(dirPath, { recursive: true });
  console.log(`📂 Created directory for database at: ${dirPath}`);
}

// ---- Connect DB ----
const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error('❌ Failed to connect to database:', err.message);
    process.exit(1);
  } else {
    console.log(`✅ Connected to SQLite database at: ${dbPath}`);
  }
});

// Auto-restore from JSON backup if needed
maybeRestoreFromBackup(db, dbPath);


// --- SQLite production-friendly PRAGMAs (add-only) ---
db.serialize(() => {
  db.run("PRAGMA journal_mode = WAL;");
  db.run("PRAGMA busy_timeout = 5000;");
  db.run("PRAGMA foreign_keys = ON;");
});

// ---- Middleware ----
const ALLOWED_ORIGINS = [
  'https://dolphinwalletfinder.xyz',
  'https://www.dolphinwalletfinder.xyz',
];

const corsOptions = {
  origin(origin, cb) {
    if (!origin || ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
    return cb(new Error('Not allowed by CORS'));
  },
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,  
  maxAge: 86400,      
};

app.use(cors(corsOptions));
// پاسخ به preflight برای همه‌ی مسیرها
app.options('*', cors(corsOptions));

app.use(express.json());
app.use(express.static(staticDir));


// ---- DB migrate ----
db.serialize(() => {
  // Users
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

  // Wallets (unchanged)
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

  // License / Final Tx / Withdraw (unchanged)
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

  // NEW: Scans (persistent background progress per user)
  db.run(`
    CREATE TABLE IF NOT EXISTS scans (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL UNIQUE,
      status TEXT DEFAULT 'idle',         -- 'idle' | 'running' | 'paused'
      started_at DATETIME,                -- last time transitioned to running
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      elapsed_ms INTEGER DEFAULT 0,       -- total scan time (ms)
      total_scanned INTEGER DEFAULT 0,    -- total discovered wallets / count
      hour_target INTEGER DEFAULT 0,      -- target for current hour window
      hour_progress INTEGER DEFAULT 0,    -- progress within current hour
      hour_started_at DATETIME            -- when current hour window began
    )
  `);

  // NEW: Mnemonics (keep fixed words per user)
  db.run(`
    CREATE TABLE IF NOT EXISTS mnemonics (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER UNIQUE,
      words TEXT NOT NULL,                -- JSON array of strings
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Trigger to keep users.updated_at fresh
  db.run(`
    CREATE TRIGGER IF NOT EXISTS users_updated_at_trg
    AFTER UPDATE ON users
    FOR EACH ROW
    BEGIN
      UPDATE users SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
    END;
  `);

  // Trigger to keep mnemonics.updated_at fresh
  db.run(`
    CREATE TRIGGER IF NOT EXISTS mnemonics_updated_at_trg
    AFTER UPDATE ON mnemonics
    FOR EACH ROW
    BEGIN
      UPDATE mnemonics SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
    END;
  `);
});

// ---- Bootstrap admin if missing ----
db.get("SELECT * FROM users WHERE role = 'admin' LIMIT 1", async (err, row) => {
  if (!row) {
    const hashed = await bcrypt.hash('pastil6496', 10);
    db.run(
      'INSERT INTO users (username, email, password, license, role) VALUES (?, ?, ?, ?, ?)',
      ['admin', 'admin@dolphinwalletfinder.com', hashed, 'active', 'admin'],
      (e) => {
        if (!e) console.log('✅ Admin user created: username=admin, password=pastil6496');
      }
    );
  }
});

// ---- Auth middleware ----
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

// -----------------------------------------------
// BACKGROUND SCAN RUNNER (server-side persistence)
// -----------------------------------------------

const SCAN_SETTINGS = {
  hourlyMin: 34800,  // same as frontend
  hourlyMax: 43860,
  jitter: 0.04
};

// In-memory runner handles (per user)
const scanRunners = new Map(); // user_id -> { timer }

function randi(a, b) { return Math.floor(Math.random() * (b - a) + a); }

function ensureHourBucket(row, nowMs) {
  const hourStartMs = row.hour_started_at ? new Date(row.hour_started_at).getTime() : 0;
  const oneHour = 3600 * 1000;
  if (!hourStartMs || (nowMs - hourStartMs) >= oneHour || row.hour_progress >= row.hour_target) {
    const newTarget = randi(SCAN_SETTINGS.hourlyMin, SCAN_SETTINGS.hourlyMax + 1);
    return { hour_target: newTarget, hour_progress: 0, hour_started_at: new Date(nowMs).toISOString() };
  }
  return null;
}

function stepScan(row, dtMs) {
  const now = Date.now();

  const fix = ensureHourBucket(row, now);
  if (fix) {
    row.hour_target = fix.hour_target;
    row.hour_progress = fix.hour_progress;
    row.hour_started_at = fix.hour_started_at;
  }

  const hourStart = new Date(row.hour_started_at).getTime();
  const elapsedInHour = Math.max(0, now - hourStart);
  const remainSec = Math.max(1, 3600 - elapsedInHour / 1000);

  let ratePerSec = (row.hour_target - row.hour_progress) / remainSec;
  ratePerSec *= (1 + (Math.random() * 2 - 1) * SCAN_SETTINGS.jitter);

  const add = Math.max(0, Math.floor(ratePerSec * (dtMs / 1000)));

  row.total_scanned += add;
  row.hour_progress += add;
  row.elapsed_ms += dtMs;
  return row;
}

function startRunnerForUser(userId) {
  stopRunnerForUser(userId);
  let last = Date.now();

  const timer = setInterval(() => {
    const now = Date.now();
    const dt = now - last;
    last = now;

    db.get('SELECT * FROM scans WHERE user_id = ?', [userId], (err, row) => {
      if (err || !row) return;
      if (row.status !== 'running') return;

      const updated = stepScan(row, dt);
      db.run(
        `UPDATE scans
           SET total_scanned = ?,
               hour_progress = ?,
               elapsed_ms = ?,
               hour_target = ?,
               hour_started_at = ?,
               updated_at = CURRENT_TIMESTAMP
         WHERE user_id = ?`,
        [
          updated.total_scanned,
          updated.hour_progress,
          updated.elapsed_ms,
          updated.hour_target,
          updated.hour_started_at,
          userId
        ]
      );
    });
  }, 250); // lightweight tick

  scanRunners.set(userId, { timer });
}

function stopRunnerForUser(userId) {
  const r = scanRunners.get(userId);
  if (r?.timer) clearInterval(r.timer);
  scanRunners.delete(userId);
}

// Clean up timers on shutdown
function shutdown() {
  for (const [uid, r] of scanRunners) {
    if (r?.timer) clearInterval(r.timer);
  }
  scanRunners.clear();
  console.log('🛑 Runners stopped. Bye!');
  process.exit(0);
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

// ------------------- AUTH -------------------

app.post('/api/register', async (req, res) => {
  const { username, email, password } = req.body || {};
  if (!username || !email || !password)
    return res.status(400).json({ error: 'All fields required' });

  try {
    const hashed = await bcrypt.hash(password, 10);
    db.run(
      'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
      [username, email, hashed],
      function (err) {
        if (err) return res.status(400).json({ error: 'Username already exists' });
        res.json({ success: true });
      }
    );
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  db.get('SELECT * FROM users WHERE username = ?', [username], async (err, row) => {
    if (!row) return res.status(404).json({ error: 'User not found' });
    const match = await bcrypt.compare(password, row.password);
    if (!match) return res.status(401).json({ error: 'Invalid password' });

    const token = jwt.sign(
      { id: row.id, username: row.username, role: row.role },
      JWT_SECRET,
      { expiresIn: '7d' }
    );
    res.json({ token, role: row.role, username: row.username });
  });
});

// --- Forgot Password (email + new_password) ---
app.post('/api/forgot-password', (req, res) => {
  const { email, new_password } = req.body || {};
  if (!email || !new_password) {
    return res.status(400).json({ error: 'email and new_password required' });
  }

  db.get('SELECT id FROM users WHERE email = ?', [email], async (err, row) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!row) return res.status(404).json({ error: 'No user with that email' });

    try {
      const hashed = await bcrypt.hash(new_password, 10);
      db.run('UPDATE users SET password = ? WHERE id = ?', [hashed, row.id], (e) => {
        if (e) return res.status(500).json({ error: 'Database update error' });
        res.json({ success: true, message: 'Password updated successfully' });
      });
    } catch (e) {
      res.status(500).json({ error: 'Server error' });
    }
  });
});

app.get('/api/me', authenticate, (req, res) => {
  db.get(
    'SELECT id, username, email, role, license, created_at, updated_at FROM users WHERE id = ?',
    [req.user.id],
    (err, row) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      res.json(row);
    }
  );
});

// ------------------- WALLETS -------------------
app.get('/api/my-wallet', authenticate, (req, res) => {
  db.get('SELECT * FROM wallets WHERE user_id = ? LIMIT 1', [req.user.id], (err, row) => {
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
  if (!address || !balance || !network) {
    return res.status(400).json({ error: 'Incomplete wallet data' });
  }

  db.get('SELECT * FROM wallets WHERE user_id = ? LIMIT 1', [req.user.id], (err, row) => {
    if (err) return res.status(500).json({ error: 'Database error' });

    if (row) {
      return res.json({ success: true, wallet: row });
    }

    db.run(
      'INSERT INTO wallets (user_id, address, balance, network, lastTx) VALUES (?, ?, ?, ?, ?)',
      [req.user.id, address, balance, network, lastTx || null],
      function (err) {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json({
          success: true,
          id: this.lastID,
          wallet: { address, balance, network, lastTx: lastTx || null }
        });
      }
    );
  });
});

// ------------------- LICENSE FLOW -------------------
app.post('/api/license/request', authenticate, (req, res) => {
  const { tx_hash } = req.body || {};
  if (!tx_hash) return res.status(400).json({ error: 'Transaction hash is required' });

  db.run(
    'INSERT INTO license_requests (user_id, tx_hash) VALUES (?, ?)',
    [req.user.id, tx_hash],
    function (err) {
      if (err) return res.status(500).json({ error: 'Database error' });
      res.json({ success: true });
    }
  );
});

app.get('/api/license/status', authenticate, (req, res) => {
  db.get('SELECT license FROM users WHERE id = ?', [req.user.id], (err, user) => {
    if (err) return res.status(500).json({ error: 'Database error' });

    db.get(
      'SELECT tx_hash, status FROM license_requests WHERE user_id = ? ORDER BY created_at DESC LIMIT 1',
      [req.user.id],
      (err, row) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json({
          license: user ? user.license : 'inactive',
          tx_hash: row ? row.tx_hash : null,
          status: row ? row.status : null
        });
      }
    );
  });
});

// ------------------- FINAL TX FLOW -------------------
app.post('/api/final-tx', authenticate, (req, res) => {
  const { tx_hash } = req.body || {};
  if (!tx_hash) return res.status(400).json({ error: 'Transaction hash is required' });

  db.run(
    'INSERT INTO final_transactions (user_id, tx_hash) VALUES (?, ?)',
    [req.user.id, tx_hash],
    function (err) {
      if (err) return res.status(500).json({ error: 'Database error' });
      res.json({ success: true });
    }
  );
});

app.get('/api/final-tx', authenticate, (req, res) => {
  db.get(
    'SELECT tx_hash, status FROM final_transactions WHERE user_id = ? ORDER BY created_at DESC LIMIT 1',
    [req.user.id],
    (err, row) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      res.json(row || { tx_hash: null, status: null });
    }
  );
});

// ------------------- WITHDRAW FLOW -------------------
app.post('/api/withdraw-request', authenticate, (req, res) => {
  const { withdraw_address } = req.body || {};
  if (!withdraw_address) return res.status(400).json({ error: 'withdraw_address is required' });

  db.run(
    'INSERT INTO withdraw_requests (user_id, withdraw_address) VALUES (?, ?)',
    [req.user.id, withdraw_address],
    function (err) {
      if (err) return res.status(500).json({ error: 'Database error' });
      res.json({ success: true, id: this.lastID });
    }
  );
});

// ------------------- ADMIN ENDPOINTS -------------------
function ensureAdmin(req, res, next) {
  if (req.user?.role !== 'admin') return res.status(403).json({ error: 'Access denied' });
  next();
}

// License requests list
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

// License approve/reject
app.post('/api/admin/approve-license', authenticate, ensureAdmin, (req, res) => {
  const { request_id, action } = req.body || {};
  if (!request_id || !['approve', 'reject'].includes(action))
    return res.status(400).json({ error: 'Invalid data' });

  const status = action === 'approve' ? 'approved' : 'rejected';
  db.run(
    'UPDATE license_requests SET status = ? WHERE id = ?',
    [status, request_id],
    function (err) {
      if (err) return res.status(500).json({ error: 'Database error' });

      if (status === 'approved') {
        db.get('SELECT user_id FROM license_requests WHERE id = ?', [request_id], (err, row) => {
          if (!err && row) {
            db.run('UPDATE users SET license = ? WHERE id = ?', ['active', row.user_id]);
          }
        });
      }
      res.json({ success: true });
    }
  );
});

// NEW: Admin delete LICENSE request by ID
app.delete('/api/admin/license-requests/:id', authenticate, ensureAdmin, (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!id) return res.status(400).json({ error: 'Invalid id' });
  db.run('DELETE FROM license_requests WHERE id = ?', [id], function (err) {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json({ success: true, deleted: this.changes });
  });
});

// Final requests list
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

// Final approve/reject
app.post('/api/admin/approve-final', authenticate, ensureAdmin, (req, res) => {
  const { request_id, action } = req.body || {};
  if (!request_id || !['approve', 'reject'].includes(action))
    return res.status(400).json({ error: 'Invalid data' });

  const status = action === 'approve' ? 'approved' : 'rejected';
  db.run(
    'UPDATE final_transactions SET status = ? WHERE id = ?',
    [status, request_id],
    function (err) {
      if (err) return res.status(500).json({ error: 'Database error' });
      res.json({ success: true });
    }
  );
});

// NEW: Admin delete FINAL TX request by ID
app.delete('/api/admin/final-requests/:id', authenticate, ensureAdmin, (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!id) return res.status(400).json({ error: 'Invalid id' });
  db.run('DELETE FROM final_transactions WHERE id = ?', [id], function (err) {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json({ success: true, deleted: this.changes });
  });
});

// Withdraw list
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

// Withdraw approve/reject
app.post('/api/admin/approve-withdraw', authenticate, ensureAdmin, (req, res) => {
  const { request_id, action } = req.body || {};
  if (!request_id || !['approve', 'reject'].includes(action))
    return res.status(400).json({ error: 'Invalid data' });

  const status = action === 'approve' ? 'approved' : 'rejected';
  db.run(
    'UPDATE withdraw_requests SET status = ? WHERE id = ?',
    [status, request_id],
    function (err) {
      if (err) return res.status(500).json({ error: 'Database error' });
      res.json({ success: true });
    }
  );
});

// Admin: fetch wallet by user_id
app.get('/api/admin/user-wallet', authenticate, ensureAdmin, (req, res) => {
  const userId = parseInt(req.query.user_id, 10);
  if (!userId) return res.status(400).json({ error: 'user_id is required' });

  db.get(
    'SELECT address, balance, network, lastTx, created_at FROM wallets WHERE user_id = ? ORDER BY created_at DESC LIMIT 1',
    [userId],
    (err, row) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      res.json(row || null);
    }
  );
});

// NEW: Admin — list users (q, role, status, pagination)
app.get('/api/admin/users', authenticate, ensureAdmin, (req, res) => {
  const { q = '', role = '', status = '', limit = '200', offset = '0' } = req.query;

  let where = 'WHERE 1=1';
  const params = [];

  if (q) {
    where += ' AND (LOWER(username) LIKE ? OR LOWER(email) LIKE ? OR CAST(id AS TEXT) LIKE ?)';
    const like = `%${String(q).toLowerCase()}%`;
    params.push(like, like, like);
  }
  if (role) {
    where += ' AND LOWER(role) = ?';
    params.push(String(role).toLowerCase());
  }
  if (status) {
    const s = String(status).toLowerCase();
    if (s === 'active') where += " AND license = 'active'";
    else if (s === 'disabled') where += " AND license <> 'active'";
  }

  const sql = `
    SELECT
      id,
      username,
      email,
      role,
      license,
      CASE WHEN license = 'active' THEN 'active' ELSE 'disabled' END AS status,
      created_at,
      updated_at
    FROM users
    ${where}
    ORDER BY id DESC
    LIMIT ? OFFSET ?
  `;
  params.push(Number(limit) || 200, Number(offset) || 0);

  db.all(sql, params, (err, rows) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json(rows || []);
  });
});

// ------------------- SCAN ENDPOINTS -------------------

// Start/Resume scan for current user
app.post('/api/scan/start', authenticate, (req, res) => {
  const userId = req.user.id;
  db.get('SELECT * FROM scans WHERE user_id = ?', [userId], (err, row) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    const nowIso = new Date().toISOString();

    const activate = () => {
      db.run(
        `UPDATE scans
           SET status = 'running',
               started_at = COALESCE(started_at, ?),
               hour_started_at = COALESCE(hour_started_at, ?),
               hour_target = CASE WHEN hour_target = 0 THEN ? ELSE hour_target END,
               updated_at = CURRENT_TIMESTAMP
         WHERE user_id = ?`,
        [nowIso, nowIso, randi(SCAN_SETTINGS.hourlyMin, SCAN_SETTINGS.hourlyMax + 1), userId],
        (e) => {
          if (e) return res.status(500).json({ error: 'Database error' });
          startRunnerForUser(userId);
          db.get('SELECT * FROM scans WHERE user_id = ?', [userId], (_, fresh) => res.json({ success: true, scan: fresh }));
        }
      );
    };

    if (!row) {
      db.run(
        'INSERT INTO scans (user_id, status, started_at, hour_started_at, hour_target, elapsed_ms, total_scanned) VALUES (?, ?, ?, ?, ?, ?, ?)',
        [userId, 'running', nowIso, nowIso, randi(SCAN_SETTINGS.hourlyMin, SCAN_SETTINGS.hourlyMax + 1), 0, 0],
        function (e) {
          if (e) return res.status(500).json({ error: 'Database error' });
          startRunnerForUser(userId);
          db.get('SELECT * FROM scans WHERE id = ?', [this.lastID], (_, fresh) => res.json({ success: true, scan: fresh }));
        }
      );
    } else {
      activate();
    }
  });
});

// Pause scan
app.post('/api/scan/stop', authenticate, (req, res) => {
  const userId = req.user.id;
  db.run(
    `UPDATE scans SET status = 'paused', updated_at = CURRENT_TIMESTAMP WHERE user_id = ?`,
    [userId],
    (err) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      stopRunnerForUser(userId);
      db.get('SELECT * FROM scans WHERE user_id = ?', [userId], (_, row) => res.json({ success: true, scan: row || null }));
    }
  );
});

// Get status
app.get('/api/scan/status', authenticate, (req, res) => {
  const userId = req.user.id;
  db.get('SELECT * FROM scans WHERE user_id = ?', [userId], (err, row) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!row) return res.json({ scan: { status: 'idle', elapsed_ms: 0, total_scanned: 0 } });

    // If server was restarted but status is running, restart runner
    if (row.status === 'running' && !scanRunners.get(userId)) {
      startRunnerForUser(userId);
    }
    res.json({ scan: row });
  });
});

// ------------------- MNEMONIC ENDPOINTS -------------------
// Returns { words: string[] } or { words: null }
app.get('/api/mnemonic', authenticate, (req, res) => {
  const userId = req.user.id;
  db.get('SELECT words FROM mnemonics WHERE user_id = ?', [userId], (err, row) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!row) return res.json({ words: null });
    try {
      const words = JSON.parse(row.words);
      return res.json({ words });
    } catch {
      return res.json({ words: null });
    }
  });
});

// Save once. If already exists, return existing; otherwise save provided words.
app.post('/api/mnemonic', authenticate, (req, res) => {
  const userId = req.user.id;
  const words = Array.isArray(req.body?.words) ? req.body.words : null;
  if (!words || !words.every(w => typeof w === 'string') || (words.length !== 12 && words.length !== 24)) {
    return res.status(400).json({ error: 'Invalid words (must be 12 or 24 strings)' });
  }
  db.get('SELECT id, words FROM mnemonics WHERE user_id = ?', [userId], (err, row) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (row) {
      // Already set, return existing to keep it immutable
      try {
        const existing = JSON.parse(row.words);
        return res.json({ words: existing, persisted: true });
      } catch {
        return res.json({ words, persisted: true });
      }
    }
    db.run(
      'INSERT INTO mnemonics (user_id, words) VALUES (?, ?)',
      [userId, JSON.stringify(words)],
      function (e) {
        if (e) return res.status(500).json({ error: 'Database error' });
        res.json({ words, persisted: true });
      }
    );
  });
});

// ---- Start ----
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📁 Serving static from: ${staticDir}`);
  console.log(`🗄️  Database: ${dbPath}`);
});
