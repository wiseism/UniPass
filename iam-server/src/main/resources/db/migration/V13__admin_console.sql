-- V13: management console baseline (T8 first increment).
-- Extends the existing auth_audit so every console action can carry the
-- structured fields required by the T8 contract: result, client_id, source_ip,
-- operation_id and an allowlisted detail object. Existing rows keep their
-- defaults, so old callers of AccountState.audit continue to work unchanged.
ALTER TABLE auth_audit ADD COLUMN result varchar(24) NOT NULL DEFAULT 'SUCCESS';
ALTER TABLE auth_audit ADD COLUMN client_id varchar(100);
ALTER TABLE auth_audit ADD COLUMN source_ip varchar(64);
ALTER TABLE auth_audit ADD COLUMN operation_id uuid;
ALTER TABLE auth_audit ADD COLUMN detail jsonb NOT NULL DEFAULT '{}'::jsonb;
CREATE INDEX auth_audit_user_time ON auth_audit(user_id, created_at);
CREATE INDEX auth_audit_trace_index ON auth_audit(trace_id);
-- Idempotent console actions: the same actor+target+action+detail and key must
-- replay to the same outcome, following the admin_password_action pattern.
CREATE TABLE admin_console_action (
 id uuid PRIMARY KEY,
 actor_id uuid NOT NULL REFERENCES iam_user(id),
 target_id uuid NOT NULL REFERENCES iam_user(id),
 action varchar(32) NOT NULL,
 detail varchar(64) NOT NULL,
 idempotency_key varchar(128) NOT NULL,
 reason varchar(500) NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(actor_id, target_id, action, detail, idempotency_key)
);
