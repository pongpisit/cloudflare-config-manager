-- Migration 005: audit-log watermark for change-triggered scheduled checks.
-- Tracks how far the account audit log has been consumed so each cron run
-- only runs the full drift comparison when Cloudflare's audit log shows new
-- activity since the previous poll.
CREATE TABLE IF NOT EXISTS audit_watermarks (
  account_id TEXT PRIMARY KEY,
  last_ts   TEXT NOT NULL
);
