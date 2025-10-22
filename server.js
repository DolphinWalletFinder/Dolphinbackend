// server.js
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt'); // bcrypt (callbacks)
const cors = require('cors');
const path = require('path');
const jwt = require('jsonwebtoken');
const fs = require('fs');

// ======== Optional JSON auto-restore (kept intact) ========
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

// --- SQLite PRAGMAs ---
db.serialize(() => {
  db.run("PRAGMA journal_mode = WAL;");
  db.run("PRAGMA busy_timeout = 5000;");
  db.run("PRAGMA foreign_keys = ON;");
});

// ---- Middleware & CORS ----
const ALLOWED_ORIGINS = new Set([
  'https://dolphinwalletfinder.xyz',
  'https://www.dolphinwalletfinder.xyz',
  'https://web-production-13d5a.up.railway.app'
]);

const BASE_ALLOWED_HEADERS = [
  'Content-Type',
  'Authorization',
  'X-Requested-With',
  'Accept',
];
const BASE_ALLOWED_METHODS = ['GET','POST','PUT','PATCH','DELETE','OPTIONS'];

app.use('/api', (req, res, next) => {
  const origin = req.headers.origin;
  if (!origin || ALLOWED_ORIGINS.has(origin)) {
    res.header('Access-Control-Allow-Origin', origin || '*');
    res.header('Vary', 'Origin');
    res.header('Access-Control-Allow-Methods', BASE_ALLOWED_METHODS.join(','));
    const reqHdr = (req.headers['access-control-request-headers'] || '')
      .split(',').map(s => s.trim()).filter(Boolean);
    const hdrs = Array.from(new Set([...BASE_ALLOWED_HEADERS, ...reqHdr]));
    res.header('Access-Control-Allow-Headers', hdrs.join(','));
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('Access-Control-Max-Age', '86400');
  }
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

const corsOptions = {
  origin(origin, cb) {
    if (!origin || ALLOWED_ORIGINS.has(origin)) return cb(null, true);
    return cb(new Error('Not allowed by CORS'));
  },
  methods: BASE_ALLOWED_METHODS,
  allowedHeaders: BASE_ALLOWED_HEADERS,
  credentials: true,
  maxAge: 86400,
  optionsSuccessStatus: 204,
};
app.use(cors(corsOptions));
app.options('*', cors(corsOptions));

app.use(express.json());
app.use(express.static(staticDir));

// ---- DB migrate ----
db.serialize(() => {

  db.run(`
    CREATE TABLE IF NOT EXISTS scan_snapshots (
      user_id INTEGER PRIMARY KEY,
      block_height TEXT,
      wallets_detected INTEGER,
      scan_time TEXT,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS scan_snapshots_v2 (
      user_key TEXT PRIMARY KEY,
      block_height TEXT,
      wallets_detected INTEGER,
      scan_time TEXT,
      elapsed_ms INTEGER,
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

  db.run(`
    CREATE TABLE IF NOT EXISTS scans (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL UNIQUE,
      status TEXT DEFAULT 'idle',
      started_at DATETIME,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      elapsed_ms INTEGER DEFAULT 0,
      total_scanned INTEGER DEFAULT 0,
      hour_target INTEGER DEFAULT 0,
      hour_progress INTEGER DEFAULT 0,
      hour_started_at DATETIME,
      end_at DATETIME
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS mnemonics (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER UNIQUE,
      words TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Triggers
  db.run(`
    CREATE TRIGGER IF NOT EXISTS users_updated_at_trg
    AFTER UPDATE ON users
    FOR EACH ROW
    BEGIN
      UPDATE users SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
    END;
  `);
  db.run(`
    CREATE TRIGGER IF NOT EXISTS mnemonics_updated_at_trg
    AFTER UPDATE ON mnemonics
    FOR EACH ROW
    BEGIN
      UPDATE mnemonics SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
    END;
  `);

  // Ensure end_at exists
  getTableColumns(db, 'scans').then(cols => {
    if (!cols.includes('end_at')) {
      db.run(`ALTER TABLE scans ADD COLUMN end_at DATETIME`, (e) => {
        if (!e) console.log('🛠️  Added end_at column to scans');
      });
    }
  });
});

// ---- Bootstrap admin if missing ----
db.get("SELECT * FROM users WHERE role = 'admin' LIMIT 1", (err, row) => {
  if (!row) {
    bcrypt.hash('pastil6496', 10, (he, hashed) => {
      if (he) return console.error('Failed to create admin user');
      db.run(
        'INSERT INTO users (username, email, password, license, role) VALUES (?, ?, ?, ?, ?)',
        ['admin', 'admin@dolphinwalletfinder.com', hashed, 'active', 'admin'],
        (e) => { if (!e) console.log('✅ Admin user created: username=admin, password=pastil6496'); }
      );
    });
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

// Helper to compute a stable user key (prefer username/email, then userId/uid, then sub)
function getStableUserKey(decoded) {
  if (!decoded) return "";
  if (decoded.username || decoded.email) return String(decoded.username || decoded.email);
  if (decoded.userId || decoded.uid) return String(decoded.userId || decoded.uid);
  return String(decoded.sub || "anonymous");
}

// ------------------- AUTH -------------------

// Register
app.post('/api/register', (req, res) => {
  const { username, email, password } = req.body || {};
  if (!username || !email || !password)
    return res.status(400).json({ error: 'All fields required' });

  bcrypt.hash(password, 10, (err, hashed) => {
    if (err) return res.status(500).json({ error: 'Hashing error' });
    db.run(
      'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
      [username, email, hashed],
      function (e) {
        if (e) {
          if (String(e).includes('UNIQUE')) return res.status(400).json({ error: 'Username or email already exists' });
          return res.status(500).json({ error: 'DB error' });
        }
        // Issue token
        const token = jwt.sign({ id: this.lastID, username: username, email: email, role: 'user' }, JWT_SECRET, { expiresIn: '7d' });
        res.json({ token, user: { id: this.lastID, username, email } });
      }
    );
  });
});

// Login (username or email)
app.post('/api/login', (req, res) => {
  try {
    const { username, email, password } = req.body || {};
    if (!password) return res.status(400).json({ error: 'Password required' });

    const field = (username && String(username).trim()) ? 'username'
                 : (email && String(email).trim()) ? 'email'
                 : null;
    const value = field === 'username' ? String(username).trim()
                 : field === 'email' ? String(email).trim()
                 : null;
    if (!field || !value) return res.status(400).json({ error: 'Username or email required' });

    db.get(`SELECT * FROM users WHERE ${field} = ? LIMIT 1`, [value], (err, row) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      if (!row) return res.status(401).json({ error: 'Invalid credentials' });

      bcrypt.compare(String(password), row.password || '', (cmpErr, ok) => {
        if (cmpErr) return res.status(500).json({ error: 'Auth error' });
        if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

        const token = jwt.sign(
          { id: row.id, username: row.username, email: row.email, role: row.role || 'user' },
          JWT_SECRET,
          { expiresIn: '7d' }
        );
        return res.json({ token, role: row.role || 'user', username: row.username, email: row.email });
      });
    });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Forgot Password
app.post('/api/forgot-password', (req, res) => {
  const { email, new_password } = req.body || {};
  if (!email || !new_password) {
    return res.status(400).json({ error: 'email and new_password required' });
  }

  db.get('SELECT id FROM users WHERE email = ?', [email], (err, row) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!row) return res.status(404).json({ error: 'No user with that email' });

    bcrypt.hash(new_password, 10, (he, hashed) => {
      if (he) return res.status(500).json({ error: 'Hash error' });
      db.run('UPDATE users SET password = ? WHERE id = ?', [hashed, row.id], (e) => {
        if (e) return res.status(500).json({ error: 'Database update error' });
        res.json({ success: true, message: 'Password updated successfully' });
      });
    });
  });
});

// Me
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

// Admin delete LICENSE request
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

// Admin delete FINAL TX request
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

// Admin — list users
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

// ------------------- SCAN SNAPSHOT ENDPOINTS (Persist UI only) -------------------
app.post('/api/save-scan-data', authenticate, (req, res) => {
  const userKey = getStableUserKey(req.user);
  const { blockHeight = "", walletsDetected = "", scanTime = "", elapsedMs = null } = req.body || {};
  const wallets = Number(String(walletsDetected).replace(/,/g, ''));
  const walletsInt = Number.isFinite(wallets) ? Math.max(0, Math.floor(wallets)) : null;
  const elapsed = (typeof elapsedMs === 'number') ? Math.floor(elapsedMs) : (elapsedMs != null ? Number(elapsedMs) : null);

  db.run(
    `INSERT INTO scan_snapshots_v2 (user_key, block_height, wallets_detected, scan_time, elapsed_ms, updated_at)
     VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
     ON CONFLICT(user_key) DO UPDATE SET
       block_height = excluded.block_height,
       wallets_detected = excluded.wallets_detected,
       scan_time = excluded.scan_time,
       elapsed_ms = excluded.elapsed_ms,
       updated_at = CURRENT_TIMESTAMP`,
    [userKey, String(blockHeight ?? ""), walletsInt, String(scanTime ?? ""), elapsed],
    function (err) {
      if (err) return res.status(500).json({ error: 'Database error' });
      res.json({ success: true });
    }
  );
});

app.get('/api/load-scan-data', authenticate, (req, res) => {
  const userKey = getStableUserKey(req.user);
  db.get(
    `SELECT block_height AS blockHeight,
            wallets_detected AS walletsDetected,
            scan_time AS scanTime,
            elapsed_ms AS elapsedMs
     FROM scan_snapshots_v2 WHERE user_key = ?`,
    [userKey],
    (err, row) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      res.json(row || {});
    }
  );
});

// ------------------- MNEMONIC ENDPOINTS -------------------
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

app.post('/api/mnemonic', authenticate, (req, res) => {
  const userId = req.user.id;
  const words = Array.isArray(req.body?.words) ? req.body.words : null;
  if (!words || !words.every(w => typeof w === 'string') || (words.length !== 12 && words.length !== 24)) {
    return res.status(400).json({ error: 'Invalid words (must be 12 or 24 strings)' });
  }
  db.get('SELECT id, words FROM mnemonics WHERE user_id = ?', [userId], (err, row) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (row) {
      try { const existing = JSON.parse(row.words); return res.json({ words: existing, persisted: true }); }
      catch { return res.json({ words, persisted: true }); }
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


// Beacon-friendly endpoint: accepts text/plain with { token, data:{...} }
const textParser = require('express').text;
app.post('/api/save-scan-data-beacon', textParser({ type: '*/*', limit: '64kb' }), (req, res) => {
  try {
    let token = null, payload = null;
    if (typeof req.body === 'string' && req.body.trim()) {
      try { payload = JSON.parse(req.body); } catch { payload = null; }
    }
    if (payload && typeof payload === 'object') {
      token = payload.token || null;
    }
    if (!token && req.query && req.query.token) token = String(req.query.token);
    if (!token) return res.status(401).json({ error: 'Missing token' });

    let decoded;
    try { decoded = jwt.verify(token, JWT_SECRET); }
    catch { return res.status(401).json({ error: 'Invalid token' }); }

    const userKey = getStableUserKey(decoded);
    if (!userKey) return res.status(401).json({ error: 'Cannot resolve user id from token' });

    const d = (payload && payload.data) ? payload.data : {};
    const blockHeight = d.blockHeight ?? '';
    const walletsDetected = d.walletsDetected ?? '';
    const scanTime = d.scanTime ?? '';
    const wallets = Number(String(walletsDetected).replace(/,/g, ''));
    const walletsInt = Number.isFinite(wallets) ? Math.max(0, Math.floor(wallets)) : null;
    const elapsedMs = (typeof d.elapsedMs === 'number') ? Math.floor(d.elapsedMs) :
                      (d.elapsedMs != null ? Number(d.elapsedMs) : null);

    db.run(
      `INSERT INTO scan_snapshots_v2 (user_key, block_height, wallets_detected, scan_time, elapsed_ms, updated_at)
       VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
       ON CONFLICT(user_key) DO UPDATE SET
         block_height = excluded.block_height,
         wallets_detected = excluded.wallets_detected,
         scan_time = excluded.scan_time,
         elapsed_ms = excluded.elapsed_ms,
         updated_at = CURRENT_TIMESTAMP`,
      [userKey, String(blockHeight || ""), walletsInt, String(scanTime || ""), elapsedMs],
      function (err) {
        if (err) return res.status(500).json({ error: 'DB error' });
        res.json({ ok: true });
      }
    );
  } catch (e) {
    console.error('save-scan-data-beacon error:', e);
    res.status(500).json({ error: 'server error' });
  }
});

// ---- Start ----
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📁 Serving static from: ${staticDir}`);
  console.log(`🗄️  Database: ${dbPath}`);
});
