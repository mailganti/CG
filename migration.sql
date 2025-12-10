-- execution_tokens table: one-time tokens for workflow execution
CREATE TABLE IF NOT EXISTS execution_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    workflow_id TEXT NOT NULL,
    token TEXT NOT NULL UNIQUE,
    created_by TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    expires_at TEXT,
    used INTEGER DEFAULT 0,
    used_at TEXT,
    used_by TEXT
);

-- execution_approval_requests table: request + approval lifecycle
CREATE TABLE IF NOT EXISTS execution_approval_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    workflow_id TEXT NOT NULL,
    requester TEXT,
    requester_email TEXT,
    requested_at TEXT DEFAULT (datetime('now')),
    status TEXT DEFAULT 'pending',  -- pending, approved, rejected
    approved_by TEXT,
    approved_at TEXT,
    token_id INTEGER, -- FK to execution_tokens.id
    note TEXT
);

-- executions table (if not present) to track runtime executions
CREATE TABLE IF NOT EXISTS executions (
    execution_id INTEGER PRIMARY KEY AUTOINCREMENT,
    workflow_id TEXT NOT NULL,
    started_at TEXT DEFAULT (datetime('now')),
    completed_at TEXT,
    status TEXT,
    user TEXT,
    log_file TEXT,
    result_json TEXT
);
