// Package store provides SQLite-backed persistence for all campaign, target,
// token, mailer profile, and template data.
package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
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
	`)
	return err
}

// ─────────────────────────────────────────────
// Campaign
// ─────────────────────────────────────────────

type CampaignRow struct {
	ID            string
	Name          string
	Description   string
	Status        int
	CreatedAt     time.Time
	StartedAt     *time.Time
	CompletedAt   *time.Time
	ArtifactsPath string
	ExportsPath   string
}

func (s *Store) UpsertCampaign(c CampaignRow) error {
	_, err := s.db.Exec(`
		INSERT INTO campaigns (id, name, description, status, created_at, started_at, completed_at, artifacts_path, exports_path)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			name=excluded.name, description=excluded.description, status=excluded.status,
			started_at=excluded.started_at, completed_at=excluded.completed_at,
			artifacts_path=excluded.artifacts_path, exports_path=excluded.exports_path`,
		c.ID, c.Name, c.Description, c.Status, c.CreatedAt, c.StartedAt, c.CompletedAt,
		c.ArtifactsPath, c.ExportsPath,
	)
	return err
}

func (s *Store) LoadCampaigns() ([]CampaignRow, error) {
	rows, err := s.db.Query(`SELECT id, name, description, status, created_at, started_at, completed_at, artifacts_path, exports_path FROM campaigns`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CampaignRow
	for rows.Next() {
		var c CampaignRow
		if err := rows.Scan(&c.ID, &c.Name, &c.Description, &c.Status,
			&c.CreatedAt, &c.StartedAt, &c.CompletedAt, &c.ArtifactsPath, &c.ExportsPath); err != nil {
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
	CampaignID   string
	TargetID     string
	TargetEmail  string
	AccessToken  string
	RefreshToken string
	IDToken      string
	TokenType    string
	ExpiresIn    int
	Scope        string
	UPN          string
	RedeemedAt   time.Time
}

func (s *Store) InsertToken(t TokenRow) error {
	_, err := s.db.Exec(`
		INSERT INTO tokens (campaign_id, target_id, target_email, access_token, refresh_token, id_token, token_type, expires_in, scope, upn, redeemed_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		t.CampaignID, t.TargetID, t.TargetEmail, t.AccessToken, t.RefreshToken, t.IDToken,
		t.TokenType, t.ExpiresIn, t.Scope, t.UPN, t.RedeemedAt,
	)
	return err
}

func (s *Store) LoadTokens(campaignID string) ([]TokenRow, error) {
	rows, err := s.db.Query(`SELECT campaign_id, target_id, target_email, access_token, refresh_token, id_token, token_type, expires_in, scope, upn, redeemed_at FROM tokens WHERE campaign_id=?`, campaignID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TokenRow
	for rows.Next() {
		var t TokenRow
		if err := rows.Scan(&t.CampaignID, &t.TargetID, &t.TargetEmail, &t.AccessToken, &t.RefreshToken,
			&t.IDToken, &t.TokenType, &t.ExpiresIn, &t.Scope, &t.UPN, &t.RedeemedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
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
	CreatedAt   time.Time
}

func (s *Store) UpsertSenderProfile(p SenderProfileRow) error {
	tls := 0
	if p.ImplicitTLS {
		tls = 1
	}
	_, err := s.db.Exec(`
		INSERT INTO sender_profiles (id, name, host, port, username, password, from_address, from_name, implicit_tls, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			name=excluded.name, host=excluded.host, port=excluded.port,
			username=excluded.username, password=excluded.password,
			from_address=excluded.from_address, from_name=excluded.from_name,
			implicit_tls=excluded.implicit_tls`,
		p.ID, p.Name, p.Host, p.Port, p.Username, p.Password, p.FromAddress, p.FromName, tls, p.CreatedAt,
	)
	return err
}

func (s *Store) LoadSenderProfiles() ([]SenderProfileRow, error) {
	rows, err := s.db.Query(`SELECT id, name, host, port, username, password, from_address, from_name, implicit_tls, created_at FROM sender_profiles`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SenderProfileRow
	for rows.Next() {
		var p SenderProfileRow
		var tls int
		if err := rows.Scan(&p.ID, &p.Name, &p.Host, &p.Port, &p.Username, &p.Password,
			&p.FromAddress, &p.FromName, &tls, &p.CreatedAt); err != nil {
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
func orEmptyDC(s []DeviceCodeRow) []DeviceCodeRow  { return orEmpty(s) }
func orEmptyTok(s []TokenRow) []TokenRow           { return orEmpty(s) }
func orEmptyER(s []EmailResultRow) []EmailResultRow { return orEmpty(s) }
