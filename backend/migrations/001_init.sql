CREATE TABLE ingestions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  filename TEXT NOT NULL,
  format TEXT NOT NULL,
  sha256 TEXT NOT NULL UNIQUE,
  is_sample INTEGER NOT NULL DEFAULT 0,
  total_records INTEGER NOT NULL DEFAULT 0,
  stored_records INTEGER NOT NULL DEFAULT 0,
  failed_records INTEGER NOT NULL DEFAULT 0,
  skipped_records INTEGER NOT NULL DEFAULT 0,
  errors TEXT NOT NULL DEFAULT '[]',
  created_at TEXT NOT NULL
);

CREATE TABLE events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ingestion_id INTEGER NOT NULL REFERENCES ingestions(id) ON DELETE CASCADE,
  ts TEXT NOT NULL,
  source TEXT,
  event_type TEXT,
  outcome TEXT,
  severity TEXT,
  src_ip TEXT,
  dst_ip TEXT,
  dst_port INTEGER,
  username TEXT,
  hostname TEXT,
  process_name TEXT,
  parent_process TEXT,
  command_line TEXT,
  domain TEXT,
  bytes_out INTEGER,
  country TEXT,
  message TEXT,
  raw TEXT NOT NULL
);
CREATE INDEX idx_events_ts ON events(ts);
CREATE INDEX idx_events_ing ON events(ingestion_id);
CREATE INDEX idx_events_type ON events(event_type, outcome);
CREATE INDEX idx_events_src ON events(src_ip);
CREATE INDEX idx_events_dst ON events(dst_ip);
CREATE INDEX idx_events_user ON events(username);
CREATE INDEX idx_events_host ON events(hostname);
CREATE INDEX idx_events_domain ON events(domain);

CREATE TABLE rules (
  id TEXT PRIMARY KEY,
  enabled INTEGER NOT NULL DEFAULT 1,
  params TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE detections (
  id TEXT PRIMARY KEY,
  dedupe_key TEXT NOT NULL UNIQUE,
  rule_id TEXT NOT NULL,
  ingestion_id INTEGER REFERENCES ingestions(id) ON DELETE CASCADE,
  severity TEXT NOT NULL,
  confidence REAL NOT NULL,
  ts TEXT NOT NULL,
  entity_type TEXT,
  entity_value TEXT,
  title TEXT NOT NULL,
  explanation TEXT NOT NULL,
  evidence TEXT NOT NULL DEFAULT '{}',
  event_ids TEXT NOT NULL DEFAULT '[]',
  status TEXT NOT NULL DEFAULT 'open',
  case_id TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX idx_det_rule ON detections(rule_id);
CREATE INDEX idx_det_status ON detections(status);
CREATE INDEX idx_det_sev ON detections(severity);

CREATE TABLE cases (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  severity TEXT NOT NULL DEFAULT 'medium',
  status TEXT NOT NULL DEFAULT 'open',
  assignee TEXT,
  findings TEXT NOT NULL DEFAULT '',
  conclusion TEXT NOT NULL DEFAULT '',
  uncertainty TEXT NOT NULL DEFAULT '',
  recommendations TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE case_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  kind TEXT NOT NULL,           -- note | evidence | detection
  ref TEXT,                     -- event id or detection id
  body TEXT NOT NULL DEFAULT '',
  snapshot TEXT,                -- JSON copy of the evidence at collection time
  created_at TEXT NOT NULL
);
CREATE INDEX idx_case_items_case ON case_items(case_id);

CREATE TABLE hunts (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  hypothesis TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'open',
  query TEXT NOT NULL DEFAULT '',
  detection_id TEXT,
  case_id TEXT,
  conclusion TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE hunt_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  hunt_id TEXT NOT NULL REFERENCES hunts(id) ON DELETE CASCADE,
  kind TEXT NOT NULL,           -- note | finding | alternative | evidence
  ref TEXT,
  body TEXT NOT NULL DEFAULT '',
  snapshot TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX idx_hunt_items_hunt ON hunt_items(hunt_id);

CREATE TABLE saved_searches (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  query TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE activity (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  action TEXT NOT NULL,
  target_type TEXT,
  target_id TEXT,
  detail TEXT
);
CREATE INDEX idx_activity_ts ON activity(ts);
