// Package mfa manages Microsoft MFA / security info methods via the
// My Sign-ins API (mysignins.microsoft.com). Requires an access token
// obtained for resource "19db86c3-b2b9-44cc-b339-36da233a3be2".
package mfa

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"
	"time"
)

const (
	signinBase = "https://mysignins.microsoft.com/api"

	// MFA method types
	MethodAuthenticatorPushCode = 1
	MethodAuthenticatorPushOnly = 2
	MethodAuthenticatorOTPOnly  = 3
	MethodMobilePhoneCall       = 5
	MethodMobilePhoneSMS        = 6
	MethodOfficePhone           = 7
	MethodEmail                 = 8
	MethodAltMobilePhone        = 11
	MethodFIDO2                 = 12
)

// Client wraps the My Sign-ins API.
type Client struct {
	accessToken string
	http        *http.Client
}

// New creates an MFA client using the provided access token.
// The token must have been obtained for resource 19db86c3-b2b9-44cc-b339-36da233a3be2.
func New(accessToken string) *Client {
	return &Client{
		accessToken: accessToken,
		http:        &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *Client) call(ctx context.Context, method, path string, body interface{}) (json.RawMessage, error) {
	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		bodyReader = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, signinBase+path, bodyReader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.accessToken)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Referer", "https://mysignins.microsoft.com/")
	req.Header.Set("Origin", "https://mysignins.microsoft.com")
	req.Header.Set("X-Ms-Sspr-Safe-Browser", "1")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("mfa request failed: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("mysignins %s %s → %d: %s", method, path, resp.StatusCode, string(raw))
	}
	return json.RawMessage(raw), nil
}

// GetSessionCtx obtains a sessionCtxV2 value required for most MFA write operations.
func (c *Client) GetSessionCtx(ctx context.Context) (string, error) {
	raw, err := c.call(ctx, "GET", "/session/authorize", nil)
	if err != nil {
		return "", err
	}
	var result struct {
		SessionCtxV2 string `json:"sessionCtxV2"`
	}
	json.Unmarshal(raw, &result)
	return result.SessionCtxV2, nil
}

// ListAvailableMethods returns which MFA methods are available for the account.
func (c *Client) ListAvailableMethods(ctx context.Context) (json.RawMessage, error) {
	return c.call(ctx, "GET", "/authenticationmethods/availablemethods", nil)
}

// AddPhoneMethod registers a phone number as an MFA method.
// phoneType: 5=MobileCall, 6=MobileSMS, 7=OfficePhone, 11=AltMobile
func (c *Client) AddPhoneMethod(ctx context.Context, phoneType int, phoneNumber, sessionCtx string) (json.RawMessage, error) {
	return c.call(ctx, "POST", "/authenticationmethods/new", map[string]interface{}{
		"type":         phoneType,
		"phoneNumber":  phoneNumber,
		"sessionCtxV2": sessionCtx,
	})
}

// AddEmailMethod registers an email address as an MFA backup method.
func (c *Client) AddEmailMethod(ctx context.Context, email, sessionCtx string) (json.RawMessage, error) {
	return c.call(ctx, "POST", "/authenticationmethods/new", map[string]interface{}{
		"type":         MethodEmail,
		"emailAddress": email,
		"sessionCtxV2": sessionCtx,
	})
}

// InitializeMobileAppRegistration starts the Authenticator app registration.
// Returns the QR code secret and verification details.
func (c *Client) InitializeMobileAppRegistration(ctx context.Context, sessionCtx string) (json.RawMessage, error) {
	return c.call(ctx, "POST", "/authenticationmethods/initializemobileapp", map[string]interface{}{
		"sessionCtxV2": sessionCtx,
	})
}

// AddMobileAppMethod completes Authenticator app registration with a secret key.
// appType: 1=Push+Code, 2=PushOnly, 3=OTPOnly
func (c *Client) AddMobileAppMethod(ctx context.Context, appType int, secretKey, sessionCtx string) (json.RawMessage, error) {
	return c.call(ctx, "POST", "/authenticationmethods/new", map[string]interface{}{
		"type":             appType,
		"secretKey":        secretKey,
		"sessionCtxV2":     sessionCtx,
	})
}

// VerifyMethod verifies a pending MFA method with a code.
func (c *Client) VerifyMethod(ctx context.Context, verificationID, code, sessionCtx string) (json.RawMessage, error) {
	return c.call(ctx, "POST", "/authenticationmethods/verify", map[string]interface{}{
		"verificationId": verificationID,
		"verificationCode": code,
		"sessionCtxV2":   sessionCtx,
	})
}

// DeleteMethod removes an MFA method from the account.
func (c *Client) DeleteMethod(ctx context.Context, methodID, sessionCtx string) error {
	_, err := c.call(ctx, "POST", "/authenticationmethods/delete", map[string]interface{}{
		"id":           methodID,
		"sessionCtxV2": sessionCtx,
	})
	return err
}

// TOTPRegistration holds a registered TOTP secret.
type TOTPRegistration struct {
	Label     string
	Secret    string // base32 secret key
	CreatedAt time.Time
}

// RegisterAsOTPApp automatically registers the tool as an Authenticator app,
// completing the full flow: initialize → add → verify.
func (c *Client) RegisterAsOTPApp(ctx context.Context, label, sessionCtx string) (*TOTPRegistration, error) {
	// Step 1: Initialize to get secret key
	initRaw, err := c.InitializeMobileAppRegistration(ctx, sessionCtx)
	if err != nil {
		return nil, fmt.Errorf("initialize: %w", err)
	}
	var initResp struct {
		SecretKey      string `json:"secretKey"`
		VerificationID string `json:"verificationId"`
	}
	if err := json.Unmarshal(initRaw, &initResp); err != nil || initResp.SecretKey == "" {
		return nil, fmt.Errorf("could not parse initialization response: %s", string(initRaw))
	}

	// Step 2: Register OTP-only Authenticator method
	_, err = c.AddMobileAppMethod(ctx, MethodAuthenticatorOTPOnly, initResp.SecretKey, sessionCtx)
	if err != nil {
		return nil, fmt.Errorf("add method: %w", err)
	}

	// Step 3: Generate current TOTP code and verify
	code, err := GenerateTOTP(initResp.SecretKey)
	if err != nil {
		return nil, fmt.Errorf("generate totp: %w", err)
	}
	_, err = c.VerifyMethod(ctx, initResp.VerificationID, code, sessionCtx)
	if err != nil {
		return nil, fmt.Errorf("verify: %w", err)
	}

	return &TOTPRegistration{
		Label:     label,
		Secret:    initResp.SecretKey,
		CreatedAt: time.Now().UTC(),
	}, nil
}

// InitializeFIDO2Registration begins FIDO2 security key registration.
// Returns WebAuthn PublicKeyCredentialCreationOptions as raw JSON.
func (c *Client) InitializeFIDO2Registration(ctx context.Context, keyName, sessionCtx string) (json.RawMessage, error) {
	return c.call(ctx, "POST", "/authenticationmethods/new", map[string]interface{}{
		"type":         MethodFIDO2,
		"name":         keyName,
		"sessionCtxV2": sessionCtx,
	})
}

// CompleteFIDO2Registration finalises FIDO2 security key registration
// by sending the AttestationResponse produced by navigator.credentials.create().
func (c *Client) CompleteFIDO2Registration(ctx context.Context, verificationID string, attestationResponse json.RawMessage, sessionCtx string) (json.RawMessage, error) {
	return c.call(ctx, "POST", "/authenticationmethods/verify", map[string]interface{}{
		"verificationId":      verificationID,
		"sessionCtxV2":        sessionCtx,
		"attestationResponse": attestationResponse,
	})
}

// ─── TOTP helpers ─────────────────────────────────────────────────────────────

// GenerateTOTP produces a current 6-digit TOTP code from a base32 secret.
func GenerateTOTP(secret string) (string, error) {
	secret = strings.ToUpper(strings.TrimSpace(secret))
	// Pad to multiple of 8
	if pad := len(secret) % 8; pad != 0 {
		secret += strings.Repeat("=", 8-pad)
	}
	key, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		return "", fmt.Errorf("invalid base32 secret: %w", err)
	}
	counter := uint64(math.Floor(float64(time.Now().Unix()) / 30))
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	h := mac.Sum(nil)
	offset := h[len(h)-1] & 0x0f
	code := binary.BigEndian.Uint32(h[offset:offset+4])&0x7fffffff % 1000000
	return fmt.Sprintf("%06d", code), nil
}
