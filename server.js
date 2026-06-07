/**
 * GRE Word App - Sync Backend
 * Node.js + Express + SQLite + JWT
 */

const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'greword-secret-key-change-in-production';

// Middleware
app.use(cors());
app.use(express.json({ limit: '10mb' }));

// Ensure data directory exists
const DATA_DIR = process.env.RENDER_DISK_MOUNT_PATH || path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

// Initialize SQLite database
const dbPath = path.join(DATA_DIR, 'greword.db');
const db = new Database(dbPath);

// Enable WAL mode for better concurrency
db.pragma('journal_mode = WAL');

// Create tables
function initDB() {
  // Users table
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Word progress table
  db.exec(`
    CREATE TABLE IF NOT EXISTS word_progress (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      word_id TEXT NOT NULL,
      interval REAL DEFAULT 0,
      ease_factor REAL DEFAULT 2.5,
      repetitions INTEGER DEFAULT 0,
      next_review INTEGER DEFAULT 0,
      last_review INTEGER DEFAULT 0,
      mistake_count INTEGER DEFAULT 0,
      updated_at INTEGER DEFAULT 0,
      UNIQUE(user_id, word_id)
    )
  `);

  // Daily logs table
  db.exec(`
    CREATE TABLE IF NOT EXISTS daily_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      date TEXT NOT NULL,
      study_count INTEGER DEFAULT 0,
      correct_count INTEGER DEFAULT 0,
      mistake_count INTEGER DEFAULT 0,
      updated_at INTEGER DEFAULT 0,
      UNIQUE(user_id, date)
    )
  `);

  // Create indexes
  db.exec(`CREATE INDEX IF NOT EXISTS idx_progress_user ON word_progress(user_id)`);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_progress_word ON word_progress(user_id, word_id)`);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_logs_user ON daily_logs(user_id)`);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_logs_date ON daily_logs(user_id, date)`);
}

initDB();

// JWT middleware
function verifyToken(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'No token provided' });
  }

  const token = authHeader.substring(7);
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.userId;
    req.userEmail = decoded.email;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ========== AUTH ENDPOINTS ==========

// Register
app.post('/api/auth/register', (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }
    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
    if (existing) {
      return res.status(409).json({ error: 'Email already registered' });
    }

    const passwordHash = bcrypt.hashSync(password, 10);
    const result = db.prepare('INSERT INTO users (email, password_hash) VALUES (?, ?)').run(email, passwordHash);

    const token = jwt.sign({ userId: result.lastInsertRowid, email }, JWT_SECRET, { expiresIn: '30d' });

    res.json({
      success: true,
      token,
      user: { id: result.lastInsertRowid, email }
    });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// Login
app.post('/api/auth/login', (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }

    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const valid = bcrypt.compareSync(password, user.password_hash);
    if (!valid) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });

    res.json({
      success: true,
      token,
      user: { id: user.id, email: user.email }
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Get current user
app.get('/api/auth/me', verifyToken, (req, res) => {
  res.json({
    success: true,
    user: { id: req.userId, email: req.userEmail }
  });
});

// ========== SYNC ENDPOINTS ==========

// Full sync (upload progress + logs)
app.post('/api/sync/full', verifyToken, (req, res) => {
  try {
    const { progress, logs } = req.body;
    const userId = req.userId;

    const upsertProgress = db.prepare(`
      INSERT INTO word_progress (user_id, word_id, interval, ease_factor, repetitions, next_review, last_review, mistake_count, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(user_id, word_id) DO UPDATE SET
        interval = excluded.interval,
        ease_factor = excluded.ease_factor,
        repetitions = excluded.repetitions,
        next_review = excluded.next_review,
        last_review = excluded.last_review,
        mistake_count = excluded.mistake_count,
        updated_at = excluded.updated_at
        WHERE excluded.updated_at > word_progress.updated_at
    `);

    const upsertLog = db.prepare(`
      INSERT INTO daily_logs (user_id, date, study_count, correct_count, mistake_count, updated_at)
      VALUES (?, ?, ?, ?, ?, ?)
      ON CONFLICT(user_id, date) DO UPDATE SET
        study_count = excluded.study_count,
        correct_count = excluded.correct_count,
        mistake_count = excluded.mistake_count,
        updated_at = excluded.updated_at
        WHERE excluded.updated_at > daily_logs.updated_at
    `);

    const insertProgress = db.prepare(`
      INSERT INTO word_progress (user_id, word_id, interval, ease_factor, repetitions, next_review, last_review, mistake_count, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(user_id, word_id) DO UPDATE SET
        interval = COALESCE((SELECT CASE WHEN ? > word_progress.updated_at THEN ? ELSE word_progress.interval END), word_progress.interval),
        ease_factor = COALESCE((SELECT CASE WHEN ? > word_progress.updated_at THEN ? ELSE word_progress.ease_factor END), word_progress.ease_factor),
        repetitions = COALESCE((SELECT CASE WHEN ? > word_progress.updated_at THEN ? ELSE word_progress.repetitions END), word_progress.repetitions),
        next_review = COALESCE((SELECT CASE WHEN ? > word_progress.updated_at THEN ? ELSE word_progress.next_review END), word_progress.next_review),
        last_review = COALESCE((SELECT CASE WHEN ? > word_progress.updated_at THEN ? ELSE word_progress.last_review END), word_progress.last_review),
        mistake_count = COALESCE((SELECT CASE WHEN ? > word_progress.updated_at THEN ? ELSE word_progress.mistake_count END), word_progress.mistake_count),
        updated_at = MAX(word_progress.updated_at, ?)
    `);

    // Use a simpler approach with individual upserts in a transaction
    db.transaction(() => {
      if (progress && Array.isArray(progress)) {
        for (const item of progress) {
          const existing = db.prepare('SELECT updated_at FROM word_progress WHERE user_id = ? AND word_id = ?').get(userId, item.word_id);
          if (!existing || item.updated_at >= existing.updated_at) {
            db.prepare(`
              INSERT INTO word_progress (user_id, word_id, interval, ease_factor, repetitions, next_review, last_review, mistake_count, updated_at)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
              ON CONFLICT(user_id, word_id) DO UPDATE SET
                interval = excluded.interval,
                ease_factor = excluded.ease_factor,
                repetitions = excluded.repetitions,
                next_review = excluded.next_review,
                last_review = excluded.last_review,
                mistake_count = excluded.mistake_count,
                updated_at = excluded.updated_at
            `).run(
              userId, item.word_id, item.interval || 0, item.ease_factor || 2.5,
              item.repetitions || 0, item.next_review || 0, item.last_review || 0,
              item.mistake_count || 0, item.updated_at || Date.now()
            );
          }
        }
      }

      if (logs && Array.isArray(logs)) {
        for (const item of logs) {
          const existing = db.prepare('SELECT updated_at FROM daily_logs WHERE user_id = ? AND date = ?').get(userId, item.date);
          if (!existing || item.updated_at >= existing.updated_at) {
            db.prepare(`
              INSERT INTO daily_logs (user_id, date, study_count, correct_count, mistake_count, updated_at)
              VALUES (?, ?, ?, ?, ?, ?)
              ON CONFLICT(user_id, date) DO UPDATE SET
                study_count = excluded.study_count,
                correct_count = excluded.correct_count,
                mistake_count = excluded.mistake_count,
                updated_at = excluded.updated_at
            `).run(
              userId, item.date, item.study_count || 0, item.correct_count || 0,
              item.mistake_count || 0, item.updated_at || Date.now()
            );
          }
        }
      }
    })();

    res.json({ success: true, message: 'Sync completed' });
  } catch (err) {
    console.error('Sync error:', err);
    res.status(500).json({ error: 'Sync failed', details: err.message });
  }
});

// Download progress
app.get('/api/sync/progress', verifyToken, (req, res) => {
  try {
    const progress = db.prepare('SELECT word_id, interval, ease_factor, repetitions, next_review, last_review, mistake_count, updated_at FROM word_progress WHERE user_id = ?').all(req.userId);
    res.json({ success: true, progress });
  } catch (err) {
    console.error('Get progress error:', err);
    res.status(500).json({ error: 'Failed to get progress' });
  }
});

// Download logs
app.get('/api/sync/logs', verifyToken, (req, res) => {
  try {
    const logs = db.prepare('SELECT date, study_count, correct_count, mistake_count, updated_at FROM daily_logs WHERE user_id = ?').all(req.userId);
    res.json({ success: true, logs });
  } catch (err) {
    console.error('Get logs error:', err);
    res.status(500).json({ error: 'Failed to get logs' });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`GRE Word Backend running on port ${PORT}`);
  console.log(`Database: ${dbPath}`);
});
