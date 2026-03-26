// Package store provides SQLite-backed persistence for all campaign, target,
// token, mailer profile, and template data.
package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// Store wraps the SQLite database.
type Store struct {
	db *sql.DB
}

// New opens (or creates) the SQLite database at dbPath and runs migrations.
func New(dbPath string) (*Store, error) {
	db, err := sql.Open("sqlite", dbPath+"?_foreign_keys=on&_journal_mode=WAL")
	if err != nil {
		return nil, fmt.Errorf("opening db: %w", err)
	}
	db.SetMaxOpenConns(1) // SQLite is single-writer
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrating db: %w", err)
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	_, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS campaigns (
			id            TEXT PRIMARY KEY,
			name          TEXT NOT NULL,
			description   TEXT NOT NULL DEFAULT '',
			status        INTEGER NOT NULL DEFAULT 0,
			created_at    DATETIME NOT NULL,
			started_at    DATETIME,
			completed_at  DATETIME,
			artifacts_path TEXT NOT NULL DEFAULT '',
			exports_path   TEXT NOT NULL DEFAULT ''
		);

		CREATE TABLE IF NOT EXISTS targets (
			id           TEXT NOT NULL,
			campaign_id  TEXT NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
			email        TEXT NOT NULL,
			display_name TEXT NOT NULL DEFAULT '',
			department   TEXT NOT NULL DEFAULT '',
			region       TEXT NOT NULL DEFAULT '',
			grp          TEXT NOT NULL DEFAULT '',
			custom_field TEXT NOT NULL DEFAULT '',
			imported_at  DATETIME NOT NULL,
			PRIMARY KEY (id, campaign_id)
		);

		CREATE TABLE IF NOT EXISTS device_codes (
			device_code      TEXT PRIMARY KEY,
			campaign_id      TEXT NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
			target_id        TEXT NOT NULL,
			target_email     TEXT NOT NULL,
			user_code        TEXT NOT NULL,
			verification_uri TEXT NOT NULL,
			expires_in       INTEGER NOT NULL DEFAULT 0,
			interval_sec     INTEGER NOT NULL DEFAULT 5,
			message          TEXT NOT NULL DEFAULT '',
			issued_at        DATETIME NOT NULL,
			expires_at       DATETIME NOT NULL
		);

		CREATE TABLE IF NOT EXISTS tokens (
			id            INTEGER PRIMARY KEY AUTOINCREMENT,
			campaign_id   TEXT NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
			target_id     TEXT NOT NULL,
			target_email  TEXT NOT NULL,
			access_token  TEXT NOT NULL DEFAULT '',
			refresh_token TEXT NOT NULL DEFAULT '',
			id_token      TEXT NOT NULL DEFAULT '',
			token_type    TEXT NOT NULL DEFAULT '',
			expires_in    INTEGER NOT NULL DEFAULT 0,
			scope         TEXT NOT NULL DEFAULT '',
			upn           TEXT NOT NULL DEFAULT '',
			redeemed_at   DATETIME NOT NULL
		);
		CREATE UNIQUE INDEX IF NOT EXISTS idx_tokens_campaign_target ON tokens(campaign_id, target_id);

		CREATE TABLE IF NOT EXISTS email_results (
			id           INTEGER PRIMARY KEY AUTOINCREMENT,
			campaign_id  TEXT NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
			target_id    TEXT NOT NULL,
			target_email TEXT NOT NULL,
			sent_at      DATETIME NOT NULL,
			success      INTEGER NOT NULL DEFAULT 0,
			error        TEXT NOT NULL DEFAULT ''
		);

		CREATE TABLE IF NOT EXISTS sender_profiles (
			id           TEXT PRIMARY KEY,
			name         TEXT NOT NULL,
			host         TEXT NOT NULL,
			port         INTEGER NOT NULL DEFAULT 587,
			username     TEXT NOT NULL DEFAULT '',
			password     TEXT NOT NULL DEFAULT '',
			from_address TEXT NOT NULL,
			from_name    TEXT NOT NULL DEFAULT '',
			implicit_tls INTEGER NOT NULL DEFAULT 0,
			created_at   DATETIME NOT NULL
		);

		CREATE TABLE IF NOT EXISTS email_templates (
			id             TEXT PRIMARY KEY,
			name           TEXT NOT NULL,
			subject        TEXT NOT NULL,
			html_body      TEXT NOT NULL,
			text_body      TEXT NOT NULL DEFAULT '',
			redirector_url TEXT NOT NULL DEFAULT '',
			created_at     DATETIME NOT NULL
		);

		CREATE TABLE IF NOT EXISTS users (
			id            TEXT PRIMARY KEY,
			username      TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			salt          TEXT NOT NULL,
			created_at    DATETIME NOT NULL
		);

		CREATE TABLE IF NOT EXISTS sessions (
			token      TEXT PRIMARY KEY,
			user_id    TEXT NOT NULL,
			created_at DATETIME NOT NULL,
			expires_at DATETIME NOT NULL
		);

		CREATE TABLE IF NOT EXISTS device_certs (
			id            TEXT PRIMARY KEY,
			label         TEXT NOT NULL,
			device_id     TEXT NOT NULL,
			join_type     INTEGER NOT NULL DEFAULT 4,
			certificate   TEXT NOT NULL DEFAULT '',
			private_key   TEXT NOT NULL DEFAULT '',
			target_domain TEXT NOT NULL DEFAULT '',
			created_at    DATETIME NOT NULL
		);

		CREATE TABLE IF NOT EXISTS primary_refresh_tokens (
			id             TEXT PRIMARY KEY,
			label          TEXT NOT NULL,
			device_cert_id TEXT NOT NULL DEFAULT '',
			prt_token      TEXT NOT NULL,
			session_key    TEXT NOT NULL,
			target_upn     TEXT NOT NULL DEFAULT '',
			tenant_id      TEXT NOT NULL DEFAULT '',
			created_at     DATETIME NOT NULL
		);

		CREATE TABLE IF NOT EXISTS winhello_keys (
			id             TEXT PRIMARY KEY,
			label          TEXT NOT NULL,
			device_cert_id TEXT NOT NULL DEFAULT '',
			key_id         TEXT NOT NULL,
			private_key    TEXT NOT NULL,
			target_upn     TEXT NOT NULL DEFAULT '',
			created_at     DATETIME NOT NULL
		);

		CREATE TABLE IF NOT EXISTS otp_secrets (
			id         TEXT PRIMARY KEY,
			label      TEXT NOT NULL,
			secret     TEXT NOT NULL,
			created_at DATETIME NOT NULL
		);

		CREATE TABLE IF NOT EXISTS request_templates (
			id         TEXT PRIMARY KEY,
			label      TEXT NOT NULL,
			method     TEXT NOT NULL DEFAULT 'GET',
			uri        TEXT NOT NULL,
			headers    TEXT NOT NULL DEFAULT '{}',
			body       TEXT NOT NULL DEFAULT '',
			created_at DATETIME NOT NULL
		);
	`)
	if err != nil {
		return err
	}
	// QR phishing scan tracking table
	if _, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS qr_scans (
			token        TEXT PRIMARY KEY,
			campaign_id  TEXT NOT NULL,
			target_id    TEXT NOT NULL,
			target_email TEXT NOT NULL,
			created_at   DATETIME NOT NULL,
			scanned_at   DATETIME,
			dc_sent      INTEGER NOT NULL DEFAULT 0
		)
	`); err != nil {
		return err
	}

	// Intune phishing tracking tables
	if _, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS intune_tokens (
			token        TEXT PRIMARY KEY,
			campaign_id  TEXT NOT NULL,
			target_id    TEXT NOT NULL,
			target_email TEXT NOT NULL,
			created_at   DATETIME NOT NULL
		);
		CREATE TABLE IF NOT EXISTS intune_captures (
			id          INTEGER PRIMARY KEY AUTOINCREMENT,
			campaign_id TEXT NOT NULL,
			target_id   TEXT NOT NULL,
			token       TEXT NOT NULL,
			url         TEXT NOT NULL,
			trigger     TEXT NOT NULL DEFAULT '',
			source_ip   TEXT NOT NULL DEFAULT '',
			captured_at DATETIME NOT NULL
		)
	`); err != nil {
		return err
	}

	// Exchanged token cache — tokens obtained via manual Token Exchange.
	if _, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS exchanged_tokens (
			id           TEXT PRIMARY KEY,
			campaign_id  TEXT NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
			target_id    TEXT NOT NULL,
			target_email TEXT NOT NULL,
			label        TEXT NOT NULL DEFAULT '',
			access_token TEXT NOT NULL DEFAULT '',
			refresh_token TEXT NOT NULL DEFAULT '',
			scope        TEXT NOT NULL DEFAULT '',
			expires_in   INTEGER NOT NULL DEFAULT 0,
			obtained_at  DATETIME NOT NULL,
			tenant_id    TEXT NOT NULL DEFAULT ''
		);
		CREATE UNIQUE INDEX IF NOT EXISTS idx_exchanged_campaign_target_label
			ON exchanged_tokens(campaign_id, target_id, label)
	`); err != nil {
		return err
	}

	// Additive column migrations — ignore "duplicate column name" errors so
	// existing databases are upgraded transparently on first run.
	for _, alter := range []string{
		`ALTER TABLE tokens ADD COLUMN tenant_id TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE tokens ADD COLUMN captured_client_id TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE campaigns ADD COLUMN qr_base_url TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE campaigns ADD COLUMN qr_dc_template_id TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE campaigns ADD COLUMN qr_dc_profile_id TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE qr_scans ADD COLUMN scan_count INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'operator'`,
		`ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE campaigns ADD COLUMN owner_id TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE sender_profiles ADD COLUMN owner_id TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE sender_profiles ADD COLUMN auth_method TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE exchanged_tokens ADD COLUMN req_scope TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE exchanged_tokens ADD COLUMN req_resource TEXT NOT NULL DEFAULT ''`,
	} {
		if _, aerr := s.db.Exec(alter); aerr != nil && !isDuplicateColumnErr(aerr) {
			return aerr
		}
	}
	// Ensure the bootstrap admin account has the admin role after upgrading existing databases.
	if _, err := s.db.Exec(`UPDATE users SET role='admin' WHERE username='admin'`); err != nil {
		return err
	}
	return nil
}

func isDuplicateColumnErr(err error) bool {
	return err != nil && strings.Contains(err.Error(), "duplicate column name")
}

// ─────────────────────────────────────────────
// Campaign
// ─────────────────────────────────────────────

type CampaignRow struct {
	ID             string
	Name           string
	Description    string
	Status         int
	CreatedAt      time.Time
	StartedAt      *time.Time
	CompletedAt    *time.Time
	ArtifactsPath  string
	ExportsPath    string
	QRBaseURL      string
	QRDCTemplateID string
	QRDCProfileID  string
	OwnerID        string
}

func (s *Store) UpsertCampaign(c CampaignRow) error {
	_, err := s.db.Exec(`
		INSERT INTO campaigns (id, name, description, status, created_at, started_at, completed_at, artifacts_path, exports_path, qr_base_url, qr_dc_template_id, qr_dc_profile_id, owner_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			name=excluded.name, description=excluded.description, status=excluded.status,
			started_at=excluded.started_at, completed_at=excluded.completed_at,
			artifacts_path=excluded.artifacts_path, exports_path=excluded.exports_path,
			qr_base_url=excluded.qr_base_url, qr_dc_template_id=excluded.qr_dc_template_id,
			qr_dc_profile_id=excluded.qr_dc_profile_id, owner_id=excluded.owner_id`,
		c.ID, c.Name, c.Description, c.Status, c.CreatedAt, c.StartedAt, c.CompletedAt,
		c.ArtifactsPath, c.ExportsPath, c.QRBaseURL, c.QRDCTemplateID, c.QRDCProfileID, c.OwnerID,
	)
	return err
}

func (s *Store) LoadCampaigns() ([]CampaignRow, error) {
	rows, err := s.db.Query(`SELECT id, name, description, status, created_at, started_at, completed_at, artifacts_path, exports_path, qr_base_url, qr_dc_template_id, qr_dc_profile_id, owner_id FROM campaigns`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CampaignRow
	for rows.Next() {
		var c CampaignRow
		if err := rows.Scan(&c.ID, &c.Name, &c.Description, &c.Status,
			&c.CreatedAt, &c.StartedAt, &c.CompletedAt, &c.ArtifactsPath, &c.ExportsPath,
			&c.QRBaseURL, &c.QRDCTemplateID, &c.QRDCProfileID, &c.OwnerID); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) DeleteCampaign(id string) error {
	_, err := s.db.Exec(`DELETE FROM campaigns WHERE id=?`, id)
	return err
}

// ─────────────────────────────────────────────
// Targets
// ─────────────────────────────────────────────

type TargetRow struct {
	ID          string
	CampaignID  string
	Email       string
	DisplayName string
	Department  string
	Region      string
	Group       string
	CustomField string
	ImportedAt  time.Time
}

func (s *Store) UpsertTarget(t TargetRow) error {
	_, err := s.db.Exec(`
		INSERT INTO targets (id, campaign_id, email, display_name, department, region, grp, custom_field, imported_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id, campaign_id) DO UPDATE SET
			email=excluded.email, display_name=excluded.display_name, department=excluded.department,
			region=excluded.region, grp=excluded.grp, custom_field=excluded.custom_field`,
		t.ID, t.CampaignID, t.Email, t.DisplayName, t.Department, t.Region, t.Group, t.CustomField, t.ImportedAt,
	)
	return err
}

func (s *Store) LoadTargets(campaignID string) ([]TargetRow, error) {
	rows, err := s.db.Query(`SELECT id, campaign_id, email, display_name, department, region, grp, custom_field, imported_at FROM targets WHERE campaign_id=?`, campaignID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TargetRow
	for rows.Next() {
		var t TargetRow
		if err := rows.Scan(&t.ID, &t.CampaignID, &t.Email, &t.DisplayName, &t.Department, &t.Region, &t.Group, &t.CustomField, &t.ImportedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) DeleteTarget(campaignID, targetID string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, q := range []string{
		`DELETE FROM email_results WHERE campaign_id=? AND target_id=?`,
		`DELETE FROM tokens WHERE campaign_id=? AND target_id=?`,
		`DELETE FROM device_codes WHERE campaign_id=? AND target_id=?`,
		`DELETE FROM targets WHERE campaign_id=? AND id=?`,
	} {
		if _, err := tx.Exec(q, campaignID, targetID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) DeleteDeviceCodeForTarget(campaignID, targetID string) error {
	_, err := s.db.Exec(`DELETE FROM device_codes WHERE campaign_id=? AND target_id=?`, campaignID, targetID)
	return err
}

// ─────────────────────────────────────────────
// Device Codes
// ─────────────────────────────────────────────

type DeviceCodeRow struct {
	DeviceCode      string
	CampaignID      string
	TargetID        string
	TargetEmail     string
	UserCode        string
	VerificationURI string
	ExpiresIn       int
	IntervalSec     int
	Message         string
	IssuedAt        time.Time
	ExpiresAt       time.Time
}

func (s *Store) UpsertDeviceCode(d DeviceCodeRow) error {
	_, err := s.db.Exec(`
		INSERT OR REPLACE INTO device_codes
		(device_code, campaign_id, target_id, target_email, user_code, verification_uri, expires_in, interval_sec, message, issued_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		d.DeviceCode, d.CampaignID, d.TargetID, d.TargetEmail, d.UserCode, d.VerificationURI,
		d.ExpiresIn, d.IntervalSec, d.Message, d.IssuedAt, d.ExpiresAt,
	)
	return err
}

func (s *Store) LoadDeviceCodes(campaignID string) ([]DeviceCodeRow, error) {
	rows, err := s.db.Query(`SELECT device_code, campaign_id, target_id, target_email, user_code, verification_uri, expires_in, interval_sec, message, issued_at, expires_at FROM device_codes WHERE campaign_id=?`, campaignID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DeviceCodeRow
	for rows.Next() {
		var d DeviceCodeRow
		if err := rows.Scan(&d.DeviceCode, &d.CampaignID, &d.TargetID, &d.TargetEmail, &d.UserCode,
			&d.VerificationURI, &d.ExpiresIn, &d.IntervalSec, &d.Message, &d.IssuedAt, &d.ExpiresAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// ─────────────────────────────────────────────
// Tokens
// ─────────────────────────────────────────────

type TokenRow struct {
	CampaignID       string
	TargetID         string
	TargetEmail      string
	AccessToken      string
	RefreshToken     string
	IDToken          string
	TokenType        string
	ExpiresIn        int
	Scope            string
	UPN              string
	RedeemedAt       time.Time
	TenantID         string // extracted from JWT tid claim
	CapturedClientID string // extracted from JWT appid/azp claim
}

func (s *Store) InsertToken(t TokenRow) error {
	_, err := s.db.Exec(`
		INSERT INTO tokens (campaign_id, target_id, target_email, access_token, refresh_token, id_token, token_type, expires_in, scope, upn, redeemed_at, tenant_id, captured_client_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(campaign_id, target_id) DO UPDATE SET
			access_token=excluded.access_token,
			refresh_token=excluded.refresh_token,
			id_token=excluded.id_token,
			token_type=excluded.token_type,
			expires_in=excluded.expires_in,
			scope=excluded.scope,
			upn=excluded.upn,
			redeemed_at=excluded.redeemed_at,
			tenant_id=excluded.tenant_id,
			captured_client_id=excluded.captured_client_id`,
		t.CampaignID, t.TargetID, t.TargetEmail, t.AccessToken, t.RefreshToken, t.IDToken,
		t.TokenType, t.ExpiresIn, t.Scope, t.UPN, t.RedeemedAt, t.TenantID, t.CapturedClientID,
	)
	return err
}

func (s *Store) LoadTokenByTargetID(campaignID, targetID string) (*TokenRow, error) {
	rows, err := s.db.Query(`
		SELECT campaign_id, target_id, target_email, access_token, refresh_token, id_token, token_type, expires_in, scope, upn, redeemed_at, tenant_id, captured_client_id
		FROM tokens WHERE campaign_id=? AND target_id=? ORDER BY redeemed_at DESC LIMIT 1`,
		campaignID, targetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, nil
	}
	var t TokenRow
	if err := rows.Scan(&t.CampaignID, &t.TargetID, &t.TargetEmail, &t.AccessToken, &t.RefreshToken,
		&t.IDToken, &t.TokenType, &t.ExpiresIn, &t.Scope, &t.UPN, &t.RedeemedAt,
		&t.TenantID, &t.CapturedClientID); err != nil {
		return nil, err
	}
	return &t, rows.Err()
}

func (s *Store) UpdateLatestToken(campaignID, targetID, accessToken, refreshToken string, refreshedAt time.Time) error {
	_, err := s.db.Exec(`
		UPDATE tokens SET access_token=?, refresh_token=?, redeemed_at=?
		WHERE campaign_id=? AND target_id=?`,
		accessToken, refreshToken, refreshedAt, campaignID, targetID,
	)
	return err
}

func (s *Store) LoadTokens(campaignID string) ([]TokenRow, error) {
	rows, err := s.db.Query(`SELECT campaign_id, target_id, target_email, access_token, refresh_token, id_token, token_type, expires_in, scope, upn, redeemed_at, tenant_id, captured_client_id FROM tokens WHERE campaign_id=?`, campaignID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TokenRow
	for rows.Next() {
		var t TokenRow
		if err := rows.Scan(&t.CampaignID, &t.TargetID, &t.TargetEmail, &t.AccessToken, &t.RefreshToken,
			&t.IDToken, &t.TokenType, &t.ExpiresIn, &t.Scope, &t.UPN, &t.RedeemedAt,
			&t.TenantID, &t.CapturedClientID); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// ─────────────────────────────────────────────
// Exchanged Tokens
// ─────────────────────────────────────────────

type ExchangedTokenRow struct {
	ID           string
	CampaignID   string
	TargetID     string
	TargetEmail  string
	Label        string
	AccessToken  string
	RefreshToken string
	Scope        string
	ExpiresIn    int
	ObtainedAt   time.Time
	TenantID     string
	ReqScope     string // original requested scope (v2)
	ReqResource  string // original requested resource (v1)
}

func (s *Store) InsertExchangedToken(t ExchangedTokenRow) error {
	_, err := s.db.Exec(`
		INSERT INTO exchanged_tokens (id, campaign_id, target_id, target_email, label, access_token, refresh_token, scope, expires_in, obtained_at, tenant_id, req_scope, req_resource)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(campaign_id, target_id, label) DO UPDATE SET
			access_token=excluded.access_token,
			refresh_token=excluded.refresh_token,
			scope=excluded.scope,
			expires_in=excluded.expires_in,
			obtained_at=excluded.obtained_at,
			tenant_id=excluded.tenant_id,
			req_scope=excluded.req_scope,
			req_resource=excluded.req_resource`,
		t.ID, t.CampaignID, t.TargetID, t.TargetEmail, t.Label,
		t.AccessToken, t.RefreshToken, t.Scope, t.ExpiresIn, t.ObtainedAt, t.TenantID,
		t.ReqScope, t.ReqResource,
	)
	return err
}

func (s *Store) LoadExchangedTokens(campaignID string) ([]ExchangedTokenRow, error) {
	rows, err := s.db.Query(`
		SELECT id, campaign_id, target_id, target_email, label, access_token, refresh_token, scope, expires_in, obtained_at, tenant_id, req_scope, req_resource
		FROM exchanged_tokens WHERE campaign_id=? ORDER BY obtained_at DESC`, campaignID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ExchangedTokenRow
	for rows.Next() {
		var t ExchangedTokenRow
		if err := rows.Scan(&t.ID, &t.CampaignID, &t.TargetID, &t.TargetEmail, &t.Label,
			&t.AccessToken, &t.RefreshToken, &t.Scope, &t.ExpiresIn, &t.ObtainedAt, &t.TenantID,
			&t.ReqScope, &t.ReqResource); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) LoadExchangedToken(campaignID, targetID, label string) (*ExchangedTokenRow, error) {
	row := s.db.QueryRow(`
		SELECT id, campaign_id, target_id, target_email, label, access_token, refresh_token, scope, expires_in, obtained_at, tenant_id, req_scope, req_resource
		FROM exchanged_tokens WHERE campaign_id=? AND target_id=? AND label=?`,
		campaignID, targetID, label)
	var t ExchangedTokenRow
	if err := row.Scan(&t.ID, &t.CampaignID, &t.TargetID, &t.TargetEmail, &t.Label,
		&t.AccessToken, &t.RefreshToken, &t.Scope, &t.ExpiresIn, &t.ObtainedAt, &t.TenantID,
		&t.ReqScope, &t.ReqResource); err != nil {
		if err.Error() == "sql: no rows in result set" {
			return nil, nil
		}
		return nil, err
	}
	return &t, nil
}

// ─────────────────────────────────────────────
// Email Results
// ─────────────────────────────────────────────

type EmailResultRow struct {
	CampaignID  string
	TargetID    string
	TargetEmail string
	SentAt      time.Time
	Success     bool
	Error       string
}

func (s *Store) InsertEmailResult(r EmailResultRow) error {
	success := 0
	if r.Success {
		success = 1
	}
	_, err := s.db.Exec(`INSERT INTO email_results (campaign_id, target_id, target_email, sent_at, success, error) VALUES (?, ?, ?, ?, ?, ?)`,
		r.CampaignID, r.TargetID, r.TargetEmail, r.SentAt, success, r.Error,
	)
	return err
}

func (s *Store) LoadEmailResults(campaignID string) ([]EmailResultRow, error) {
	rows, err := s.db.Query(`SELECT campaign_id, target_id, target_email, sent_at, success, error FROM email_results WHERE campaign_id=?`, campaignID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EmailResultRow
	for rows.Next() {
		var r EmailResultRow
		var success int
		if err := rows.Scan(&r.CampaignID, &r.TargetID, &r.TargetEmail, &r.SentAt, &success, &r.Error); err != nil {
			return nil, err
		}
		r.Success = success == 1
		out = append(out, r)
	}
	return out, rows.Err()
}

// ─────────────────────────────────────────────
// Sender Profiles
// ─────────────────────────────────────────────

type SenderProfileRow struct {
	ID          string
	Name        string
	Host        string
	Port        int
	Username    string
	Password    string
	FromAddress string
	FromName    string
	ImplicitTLS bool
	AuthMethod  string
	CreatedAt   time.Time
	OwnerID     string
}

func (s *Store) UpsertSenderProfile(p SenderProfileRow) error {
	tls := 0
	if p.ImplicitTLS {
		tls = 1
	}
	_, err := s.db.Exec(`
		INSERT INTO sender_profiles (id, name, host, port, username, password, from_address, from_name, implicit_tls, auth_method, created_at, owner_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			name=excluded.name, host=excluded.host, port=excluded.port,
			username=excluded.username, password=excluded.password,
			from_address=excluded.from_address, from_name=excluded.from_name,
			implicit_tls=excluded.implicit_tls, auth_method=excluded.auth_method,
			owner_id=excluded.owner_id`,
		p.ID, p.Name, p.Host, p.Port, p.Username, p.Password, p.FromAddress, p.FromName, tls, p.AuthMethod, p.CreatedAt, p.OwnerID,
	)
	return err
}

func (s *Store) LoadSenderProfiles() ([]SenderProfileRow, error) {
	rows, err := s.db.Query(`SELECT id, name, host, port, username, password, from_address, from_name, implicit_tls, COALESCE(auth_method,''), created_at, COALESCE(owner_id,'') FROM sender_profiles`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SenderProfileRow
	for rows.Next() {
		var p SenderProfileRow
		var tls int
		if err := rows.Scan(&p.ID, &p.Name, &p.Host, &p.Port, &p.Username, &p.Password,
			&p.FromAddress, &p.FromName, &tls, &p.AuthMethod, &p.CreatedAt, &p.OwnerID); err != nil {
			return nil, err
		}
		p.ImplicitTLS = tls == 1
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) LoadSenderProfilesByOwner(ownerID string) ([]SenderProfileRow, error) {
	rows, err := s.db.Query(`SELECT id, name, host, port, username, password, from_address, from_name, implicit_tls, COALESCE(auth_method,''), created_at, COALESCE(owner_id,'') FROM sender_profiles WHERE owner_id=? OR owner_id=''`, ownerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SenderProfileRow
	for rows.Next() {
		var p SenderProfileRow
		var tls int
		if err := rows.Scan(&p.ID, &p.Name, &p.Host, &p.Port, &p.Username, &p.Password,
			&p.FromAddress, &p.FromName, &tls, &p.AuthMethod, &p.CreatedAt, &p.OwnerID); err != nil {
			return nil, err
		}
		p.ImplicitTLS = tls == 1
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) DeleteSenderProfile(id string) error {
	_, err := s.db.Exec(`DELETE FROM sender_profiles WHERE id=?`, id)
	return err
}

// ─────────────────────────────────────────────
// Email Templates
// ─────────────────────────────────────────────

type EmailTemplateRow struct {
	ID            string
	Name          string
	Subject       string
	HTMLBody      string
	TextBody      string
	RedirectorURL string
	CreatedAt     time.Time
}

func (s *Store) UpsertEmailTemplate(t EmailTemplateRow) error {
	_, err := s.db.Exec(`
		INSERT INTO email_templates (id, name, subject, html_body, text_body, redirector_url, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			name=excluded.name, subject=excluded.subject, html_body=excluded.html_body,
			text_body=excluded.text_body, redirector_url=excluded.redirector_url`,
		t.ID, t.Name, t.Subject, t.HTMLBody, t.TextBody, t.RedirectorURL, t.CreatedAt,
	)
	return err
}

func (s *Store) LoadEmailTemplates() ([]EmailTemplateRow, error) {
	rows, err := s.db.Query(`SELECT id, name, subject, html_body, text_body, redirector_url, created_at FROM email_templates`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EmailTemplateRow
	for rows.Next() {
		var t EmailTemplateRow
		if err := rows.Scan(&t.ID, &t.Name, &t.Subject, &t.HTMLBody, &t.TextBody, &t.RedirectorURL, &t.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) DeleteEmailTemplate(id string) error {
	_, err := s.db.Exec(`DELETE FROM email_templates WHERE id=?`, id)
	return err
}

// ─────────────────────────────────────────────
// Export
// ─────────────────────────────────────────────

// CampaignExport holds the complete evidence package for one campaign.
type CampaignExport struct {
	Campaign     CampaignRow      `json:"campaign"`
	Targets      []TargetRow      `json:"targets"`
	DeviceCodes  []DeviceCodeRow  `json:"device_codes"`
	Tokens       []TokenRow       `json:"tokens"`
	EmailResults []EmailResultRow `json:"email_results"`
	ExportedAt   time.Time        `json:"exported_at"`
}

func (s *Store) ExportCampaign(id string) (*CampaignExport, error) {
	campaigns, err := s.LoadCampaigns()
	if err != nil {
		return nil, err
	}
	var camp *CampaignRow
	for i := range campaigns {
		if campaigns[i].ID == id {
			camp = &campaigns[i]
			break
		}
	}
	if camp == nil {
		return nil, fmt.Errorf("campaign %s not found", id)
	}

	targets, err := s.LoadTargets(id)
	if err != nil {
		return nil, err
	}
	codes, err := s.LoadDeviceCodes(id)
	if err != nil {
		return nil, err
	}
	tokens, err := s.LoadTokens(id)
	if err != nil {
		return nil, err
	}
	emailResults, err := s.LoadEmailResults(id)
	if err != nil {
		return nil, err
	}

	return &CampaignExport{
		Campaign:     *camp,
		Targets:      orEmpty(targets),
		DeviceCodes:  orEmptyDC(codes),
		Tokens:       orEmptyTok(tokens),
		EmailResults: orEmptyER(emailResults),
		ExportedAt:   time.Now().UTC(),
	}, nil
}

func (e *CampaignExport) JSON() ([]byte, error) {
	return json.MarshalIndent(e, "", "  ")
}

func orEmpty[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}
func orEmptyDC(s []DeviceCodeRow) []DeviceCodeRow   { return orEmpty(s) }
func orEmptyTok(s []TokenRow) []TokenRow            { return orEmpty(s) }
func orEmptyER(s []EmailResultRow) []EmailResultRow { return orEmpty(s) }

// ─────────────────────────────────────────────
// Users
// ─────────────────────────────────────────────

type UserRow struct {
	ID                 string
	Username           string
	PasswordHash       string
	Salt               string
	CreatedAt          time.Time
	Role               string
	MustChangePassword bool
}

func (s *Store) CreateUser(id, username, passwordHash, salt string) error {
	return s.CreateUserFull(id, username, passwordHash, salt, "admin", false)
}

func (s *Store) CreateUserFull(id, username, passwordHash, salt, role string, mustChangePassword bool) error {
	mcp := 0
	if mustChangePassword {
		mcp = 1
	}
	_, err := s.db.Exec(
		`INSERT INTO users (id, username, password_hash, salt, created_at, role, must_change_password) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		id, username, passwordHash, salt, time.Now().UTC(), role, mcp,
	)
	return err
}

func (s *Store) GetUserByUsername(username string) (*UserRow, error) {
	row := s.db.QueryRow(
		`SELECT id, username, password_hash, salt, created_at, COALESCE(role,'operator'), COALESCE(must_change_password,0) FROM users WHERE username=?`, username)
	var u UserRow
	var mcp int
	if err := row.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Salt, &u.CreatedAt, &u.Role, &mcp); err != nil {
		if err.Error() == "sql: no rows in result set" {
			return nil, nil
		}
		return nil, err
	}
	u.MustChangePassword = mcp == 1
	return &u, nil
}

func (s *Store) GetUserByID(id string) (*UserRow, error) {
	row := s.db.QueryRow(
		`SELECT id, username, password_hash, salt, created_at, COALESCE(role,'operator'), COALESCE(must_change_password,0) FROM users WHERE id=?`, id)
	var u UserRow
	var mcp int
	if err := row.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Salt, &u.CreatedAt, &u.Role, &mcp); err != nil {
		if strings.Contains(err.Error(), "no rows") {
			return nil, nil
		}
		return nil, err
	}
	u.MustChangePassword = mcp == 1
	return &u, nil
}

func (s *Store) ListUsers() ([]UserRow, error) {
	rows, err := s.db.Query(`SELECT id, username, password_hash, salt, created_at, COALESCE(role,'operator'), COALESCE(must_change_password,0) FROM users ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []UserRow
	for rows.Next() {
		var u UserRow
		var mcp int
		if err := rows.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Salt, &u.CreatedAt, &u.Role, &mcp); err != nil {
			return nil, err
		}
		u.MustChangePassword = mcp == 1
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *Store) UpdateUserByID(id, username, role string, mustChangePassword bool) error {
	mcp := 0
	if mustChangePassword {
		mcp = 1
	}
	_, err := s.db.Exec(`UPDATE users SET username=?, role=?, must_change_password=? WHERE id=?`, username, role, mcp, id)
	return err
}

func (s *Store) UpdateUserPasswordByID(id, passwordHash, salt string, mustChangePassword bool) error {
	mcp := 0
	if mustChangePassword {
		mcp = 1
	}
	_, err := s.db.Exec(`UPDATE users SET password_hash=?, salt=?, must_change_password=? WHERE id=?`, passwordHash, salt, mcp, id)
	return err
}

func (s *Store) DeleteUser(id string) error {
	_, err := s.db.Exec(`DELETE FROM users WHERE id=?`, id)
	return err
}

func (s *Store) CountUsers() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

func (s *Store) UpdateUserPassword(username, passwordHash, salt string) error {
	_, err := s.db.Exec(
		`UPDATE users SET password_hash=?, salt=? WHERE username=?`,
		passwordHash, salt, username,
	)
	return err
}

// ListAdminUserIDs returns the IDs of all users with role='admin'.
func (s *Store) ListAdminUserIDs() ([]string, error) {
	rows, err := s.db.Query(`SELECT id FROM users WHERE role='admin'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// ─────────────────────────────────────────────
// Sessions
// ─────────────────────────────────────────────

type SessionRow struct {
	Token     string
	UserID    string
	CreatedAt time.Time
	ExpiresAt time.Time
}

func (s *Store) CreateSession(token, userID string, expiresAt time.Time) error {
	_, err := s.db.Exec(
		`INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)`,
		token, userID, time.Now().UTC(), expiresAt,
	)
	return err
}

func (s *Store) GetSession(token string) (*SessionRow, error) {
	row := s.db.QueryRow(
		`SELECT token, user_id, created_at, expires_at FROM sessions WHERE token=?`, token)
	var sess SessionRow
	if err := row.Scan(&sess.Token, &sess.UserID, &sess.CreatedAt, &sess.ExpiresAt); err != nil {
		if err.Error() == "sql: no rows in result set" {
			return nil, nil
		}
		return nil, err
	}
	return &sess, nil
}

func (s *Store) DeleteSession(token string) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE token=?`, token)
	return err
}

func (s *Store) CleanupSessions() error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE expires_at < ?`, time.Now().UTC())
	return err
}

// ─────────────────────────────────────────────
// Device Certificates
// ─────────────────────────────────────────────

type DeviceCertRow struct {
	ID           string
	Label        string
	DeviceID     string
	JoinType     int
	Certificate  string
	PrivateKey   string
	TargetDomain string
	CreatedAt    time.Time
}

func (s *Store) InsertDeviceCert(r DeviceCertRow) error {
	_, err := s.db.Exec(`INSERT INTO device_certs (id,label,device_id,join_type,certificate,private_key,target_domain,created_at) VALUES (?,?,?,?,?,?,?,?)`,
		r.ID, r.Label, r.DeviceID, r.JoinType, r.Certificate, r.PrivateKey, r.TargetDomain, r.CreatedAt)
	return err
}

func (s *Store) ListDeviceCerts() ([]DeviceCertRow, error) {
	rows, err := s.db.Query(`SELECT id,label,device_id,join_type,certificate,private_key,target_domain,created_at FROM device_certs ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DeviceCertRow
	for rows.Next() {
		var r DeviceCertRow
		if err := rows.Scan(&r.ID, &r.Label, &r.DeviceID, &r.JoinType, &r.Certificate, &r.PrivateKey, &r.TargetDomain, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) GetDeviceCert(id string) (*DeviceCertRow, error) {
	row := s.db.QueryRow(`SELECT id,label,device_id,join_type,certificate,private_key,target_domain,created_at FROM device_certs WHERE id=?`, id)
	var r DeviceCertRow
	if err := row.Scan(&r.ID, &r.Label, &r.DeviceID, &r.JoinType, &r.Certificate, &r.PrivateKey, &r.TargetDomain, &r.CreatedAt); err != nil {
		return nil, err
	}
	return &r, nil
}

func (s *Store) DeleteDeviceCert(id string) error {
	_, err := s.db.Exec(`DELETE FROM device_certs WHERE id=?`, id)
	return err
}

// ─────────────────────────────────────────────
// Primary Refresh Tokens
// ─────────────────────────────────────────────

type PRTRow struct {
	ID           string
	Label        string
	DeviceCertID string
	PRTToken     string
	SessionKey   string
	TargetUPN    string
	TenantID     string
	CreatedAt    time.Time
}

func (s *Store) InsertPRT(r PRTRow) error {
	_, err := s.db.Exec(`INSERT INTO primary_refresh_tokens (id,label,device_cert_id,prt_token,session_key,target_upn,tenant_id,created_at) VALUES (?,?,?,?,?,?,?,?)`,
		r.ID, r.Label, r.DeviceCertID, r.PRTToken, r.SessionKey, r.TargetUPN, r.TenantID, r.CreatedAt)
	return err
}

func (s *Store) ListPRTs() ([]PRTRow, error) {
	rows, err := s.db.Query(`SELECT id,label,device_cert_id,prt_token,session_key,target_upn,tenant_id,created_at FROM primary_refresh_tokens ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PRTRow
	for rows.Next() {
		var r PRTRow
		if err := rows.Scan(&r.ID, &r.Label, &r.DeviceCertID, &r.PRTToken, &r.SessionKey, &r.TargetUPN, &r.TenantID, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) GetPRT(id string) (*PRTRow, error) {
	row := s.db.QueryRow(`SELECT id,label,device_cert_id,prt_token,session_key,target_upn,tenant_id,created_at FROM primary_refresh_tokens WHERE id=?`, id)
	var r PRTRow
	if err := row.Scan(&r.ID, &r.Label, &r.DeviceCertID, &r.PRTToken, &r.SessionKey, &r.TargetUPN, &r.TenantID, &r.CreatedAt); err != nil {
		return nil, err
	}
	return &r, nil
}

func (s *Store) DeletePRT(id string) error {
	_, err := s.db.Exec(`DELETE FROM primary_refresh_tokens WHERE id=?`, id)
	return err
}

// ─────────────────────────────────────────────
// WinHello Keys
// ─────────────────────────────────────────────

type WinHelloKeyRow struct {
	ID           string
	Label        string
	DeviceCertID string
	KeyID        string
	PrivateKey   string
	TargetUPN    string
	CreatedAt    time.Time
}

func (s *Store) InsertWinHelloKey(r WinHelloKeyRow) error {
	_, err := s.db.Exec(`INSERT INTO winhello_keys (id,label,device_cert_id,key_id,private_key,target_upn,created_at) VALUES (?,?,?,?,?,?,?)`,
		r.ID, r.Label, r.DeviceCertID, r.KeyID, r.PrivateKey, r.TargetUPN, r.CreatedAt)
	return err
}

func (s *Store) ListWinHelloKeys() ([]WinHelloKeyRow, error) {
	rows, err := s.db.Query(`SELECT id,label,device_cert_id,key_id,private_key,target_upn,created_at FROM winhello_keys ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []WinHelloKeyRow
	for rows.Next() {
		var r WinHelloKeyRow
		if err := rows.Scan(&r.ID, &r.Label, &r.DeviceCertID, &r.KeyID, &r.PrivateKey, &r.TargetUPN, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) DeleteWinHelloKey(id string) error {
	_, err := s.db.Exec(`DELETE FROM winhello_keys WHERE id=?`, id)
	return err
}

// ─────────────────────────────────────────────
// OTP Secrets
// ─────────────────────────────────────────────

type OTPSecretRow struct {
	ID        string
	Label     string
	Secret    string
	CreatedAt time.Time
}

func (s *Store) InsertOTPSecret(r OTPSecretRow) error {
	_, err := s.db.Exec(`INSERT INTO otp_secrets (id,label,secret,created_at) VALUES (?,?,?,?)`,
		r.ID, r.Label, r.Secret, r.CreatedAt)
	return err
}

func (s *Store) ListOTPSecrets() ([]OTPSecretRow, error) {
	rows, err := s.db.Query(`SELECT id,label,secret,created_at FROM otp_secrets ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []OTPSecretRow
	for rows.Next() {
		var r OTPSecretRow
		if err := rows.Scan(&r.ID, &r.Label, &r.Secret, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) DeleteOTPSecret(id string) error {
	_, err := s.db.Exec(`DELETE FROM otp_secrets WHERE id=?`, id)
	return err
}

// ─────────────────────────────────────────────
// Request Templates
// ─────────────────────────────────────────────

type RequestTemplateRow struct {
	ID        string
	Label     string
	Method    string
	URI       string
	Headers   string
	Body      string
	CreatedAt time.Time
}

func (s *Store) InsertRequestTemplate(r RequestTemplateRow) error {
	_, err := s.db.Exec(`INSERT INTO request_templates (id,label,method,uri,headers,body,created_at) VALUES (?,?,?,?,?,?,?)`,
		r.ID, r.Label, r.Method, r.URI, r.Headers, r.Body, r.CreatedAt)
	return err
}

func (s *Store) ListRequestTemplates() ([]RequestTemplateRow, error) {
	rows, err := s.db.Query(`SELECT id,label,method,uri,headers,body,created_at FROM request_templates ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RequestTemplateRow
	for rows.Next() {
		var r RequestTemplateRow
		if err := rows.Scan(&r.ID, &r.Label, &r.Method, &r.URI, &r.Headers, &r.Body, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) DeleteRequestTemplate(id string) error {
	_, err := s.db.Exec(`DELETE FROM request_templates WHERE id=?`, id)
	return err
}

// ─────────────────────────────────────────────
// QR Scan Tracking
// ─────────────────────────────────────────────

type QRScanRow struct {
	Token       string     `json:"token"`
	CampaignID  string     `json:"campaign_id"`
	TargetID    string     `json:"target_id"`
	TargetEmail string     `json:"target_email"`
	CreatedAt   time.Time  `json:"created_at"`
	ScannedAt   *time.Time `json:"scanned_at"`
	DCSent      bool       `json:"dc_sent"`
	ScanCount   int        `json:"scan_count"`
}

func (s *Store) UpsertQRScan(r QRScanRow) error {
	_, err := s.db.Exec(`
		INSERT INTO qr_scans (token, campaign_id, target_id, target_email, created_at, scanned_at, dc_sent, scan_count)
		VALUES (?, ?, ?, ?, ?, ?, ?, 0)
		ON CONFLICT(token) DO UPDATE SET
			scanned_at=excluded.scanned_at, dc_sent=excluded.dc_sent`,
		r.Token, r.CampaignID, r.TargetID, r.TargetEmail, r.CreatedAt, r.ScannedAt, boolToInt(r.DCSent),
	)
	return err
}

func (s *Store) GetQRScan(token string) (*QRScanRow, error) {
	row := s.db.QueryRow(`
		SELECT token, campaign_id, target_id, target_email, created_at, scanned_at, dc_sent, scan_count
		FROM qr_scans WHERE token=?`, token)
	var r QRScanRow
	var dcSent, scanCount int
	var scannedAt *string // scan as string to avoid *time.Time NULL parsing issues
	if err := row.Scan(&r.Token, &r.CampaignID, &r.TargetID, &r.TargetEmail, &r.CreatedAt, &scannedAt, &dcSent, &scanCount); err != nil {
		if err.Error() == "sql: no rows in result set" {
			return nil, nil
		}
		return nil, err
	}
	r.DCSent = dcSent != 0
	r.ScanCount = scanCount
	if scannedAt != nil {
		t, _ := time.Parse(time.RFC3339Nano, *scannedAt)
		if t.IsZero() {
			t, _ = time.Parse("2006-01-02T15:04:05Z", *scannedAt)
		}
		if !t.IsZero() {
			r.ScannedAt = &t
		}
	}
	return &r, nil
}

// MarkQRScanned records the scan timestamp and increments the scan counter.
func (s *Store) MarkQRScanned(token string, at time.Time) error {
	_, err := s.db.Exec(
		`UPDATE qr_scans SET scanned_at=?, scan_count=scan_count+1 WHERE token=?`,
		at, token,
	)
	return err
}

func (s *Store) MarkQRDCSent(token string) error {
	_, err := s.db.Exec(`UPDATE qr_scans SET dc_sent=1 WHERE token=?`, token)
	return err
}

func (s *Store) ListQRScans(campaignID string) ([]QRScanRow, error) {
	rows, err := s.db.Query(`
		SELECT token, campaign_id, target_id, target_email, created_at, scanned_at, dc_sent, scan_count
		FROM qr_scans WHERE campaign_id=? ORDER BY created_at DESC`, campaignID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []QRScanRow
	for rows.Next() {
		var r QRScanRow
		var dcSent, scanCount int
		var scannedAt *string
		if err := rows.Scan(&r.Token, &r.CampaignID, &r.TargetID, &r.TargetEmail, &r.CreatedAt, &scannedAt, &dcSent, &scanCount); err != nil {
			return nil, err
		}
		r.DCSent = dcSent != 0
		r.ScanCount = scanCount
		if scannedAt != nil {
			t, _ := time.Parse(time.RFC3339Nano, *scannedAt)
			if t.IsZero() {
				t, _ = time.Parse("2006-01-02T15:04:05Z", *scannedAt)
			}
			if !t.IsZero() {
				r.ScannedAt = &t
			}
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// ─────────────────────────────────────────────
// Intune Token Tracking
// ─────────────────────────────────────────────

type IntuneTokenRow struct {
	Token       string
	CampaignID  string
	TargetID    string
	TargetEmail string
	CreatedAt   time.Time
}

func (s *Store) UpsertIntuneToken(r IntuneTokenRow) error {
	_, err := s.db.Exec(`
		INSERT INTO intune_tokens (token, campaign_id, target_id, target_email, created_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(token) DO UPDATE SET
			campaign_id=excluded.campaign_id, target_id=excluded.target_id,
			target_email=excluded.target_email`,
		r.Token, r.CampaignID, r.TargetID, r.TargetEmail, r.CreatedAt,
	)
	return err
}

func (s *Store) GetIntuneTokenInfo(token string) (campaignID, targetID string, found bool) {
	row := s.db.QueryRow(`
		SELECT campaign_id, target_id FROM intune_tokens WHERE token=?`, token)
	var cid, tid string
	if err := row.Scan(&cid, &tid); err != nil {
		return "", "", false
	}
	return cid, tid, true
}

// ─────────────────────────────────────────────
// Intune Capture Tracking
// ─────────────────────────────────────────────

type IntuneCaptureRow struct {
	ID         int64     `json:"id"`
	CampaignID string    `json:"campaign_id"`
	TargetID   string    `json:"target_id"`
	Token      string    `json:"token"`
	URL        string    `json:"url"`
	Trigger    string    `json:"trigger"`
	SourceIP   string    `json:"source_ip"`
	CapturedAt time.Time `json:"captured_at"`
}

func (s *Store) InsertIntuneCapture(r IntuneCaptureRow) error {
	result, err := s.db.Exec(`
		INSERT INTO intune_captures (campaign_id, target_id, token, url, trigger, source_ip, captured_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		r.CampaignID, r.TargetID, r.Token, r.URL, r.Trigger, r.SourceIP, r.CapturedAt,
	)
	if err != nil {
		return err
	}
	r.ID, _ = result.LastInsertId()
	return nil
}

func (s *Store) ListIntuneCaptures(campaignID string) ([]IntuneCaptureRow, error) {
	rows, err := s.db.Query(`
		SELECT id, campaign_id, target_id, token, url, trigger, source_ip, captured_at
		FROM intune_captures WHERE campaign_id=? ORDER BY captured_at DESC`, campaignID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []IntuneCaptureRow
	for rows.Next() {
		var r IntuneCaptureRow
		if err := rows.Scan(&r.ID, &r.CampaignID, &r.TargetID, &r.Token, &r.URL, &r.Trigger, &r.SourceIP, &r.CapturedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
