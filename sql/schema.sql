-- Compliance analytics schema (SQLite).
-- See queries.sql (same directory) for the analysis patterns.

CREATE TABLE IF NOT EXISTS controls (
  id TEXT PRIMARY KEY, title TEXT, framework TEXT, ref TEXT, owner_team TEXT, severity TEXT);

CREATE TABLE IF NOT EXISTS control_results (        -- append-only history
  id INTEGER PRIMARY KEY AUTOINCREMENT, control_id TEXT, account TEXT, status TEXT, tested_at TEXT);

CREATE TABLE IF NOT EXISTS assets (
  id TEXT PRIMARY KEY, name TEXT, type TEXT, account TEXT, owner_team TEXT, environment TEXT, created_at TEXT);

CREATE TABLE IF NOT EXISTS owners (team TEXT PRIMARY KEY, email TEXT, manager TEXT);

CREATE TABLE IF NOT EXISTS findings (
  id TEXT PRIMARY KEY, asset_id TEXT, control_id TEXT, severity TEXT, status TEXT,
  created_at TEXT, resolved_at TEXT);

CREATE TABLE IF NOT EXISTS tickets (
  id TEXT PRIMARY KEY, finding_id TEXT, status TEXT, assignee_team TEXT, created_at TEXT, closed_at TEXT);

CREATE TABLE IF NOT EXISTS exceptions (
  id TEXT PRIMARY KEY, control_id TEXT, justifier TEXT, expires_at TEXT, status TEXT);

CREATE INDEX IF NOT EXISTS idx_results_control_time ON control_results (control_id, tested_at);
