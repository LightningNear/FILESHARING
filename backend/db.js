const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const DB_PATH = path.join(__dirname, 'lightshare.db');
const db = new sqlite3.Database(DB_PATH);

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS workspaces (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      normalized_name TEXT NOT NULL,
      creator TEXT NOT NULL,
      active INTEGER DEFAULT 1,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Unique index to ensure no two active workspaces share same normalized_name
  db.run(`
    CREATE UNIQUE INDEX IF NOT EXISTS ux_workspaces_normalized_active
    ON workspaces(normalized_name)
    WHERE active = 1
  `);

  // Optional: keep the original unique constraint on (name, active) if you want
  db.run(`
    CREATE UNIQUE INDEX IF NOT EXISTS ux_workspaces_name_active
    ON workspaces(name, active)
  `);
});

module.exports = db;
