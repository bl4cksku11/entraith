// Package devicereg implements Entra ID device registration (Azure AD Join /
// Workplace Join). A registered fake device provides the certificate required
// to request Primary Refresh Tokens (PRTs).
package devicereg

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"
)

const deviceRegEndpoint = "https://enterpriseregistration.windows.net/EnrollmentServer/device/?api-version=2.0"

// JoinType mirrors the Entra ID device join category.
const (
	JoinTypeAADJoined   = 0 // Azure AD Joined
	JoinTypeRegistered  = 4 // Azure AD Registered (Workplace Join)
)

// DeviceCert holds all data for a registered virtual device.
type DeviceCert struct {
	ID           string    `json:"id"`           // internal row ID
	Label        string    `json:"label"`        // friendly name
	DeviceID     string    `json:"device_id"`    // UUID assigned by Entra
	JoinType     int       `json:"join_type"`
	Certificate  string    `json:"certificate"`  // base64 DER
	PrivateKeyPEM string   `json:"private_key"`  // PEM PKCS#1
	TargetDomain string    `json:"target_domain"`
	CreatedAt    time.Time `json:"created_at"`

	// Parsed fields (not persisted)
	parsedKey  *rsa.PrivateKey
	parsedCert *x509.Certificate
}

// PrivateKey returns the parsed RSA private key.
func (d *DeviceCert) PrivateKey() (*rsa.PrivateKey, error) {
	if d.parsedKey != nil {
		return d.parsedKey, nil
	}
	block, _ := pem.Decode([]byte(d.PrivateKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("invalid private key PEM")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	d.parsedKey = key
	return key, nil
}

// ParsedCert returns the parsed DER certificate.
func (d *DeviceCert) ParsedCert() (*x509.Certificate, error) {
	if d.parsedCert != nil {
		return d.parsedCert, nil
	}
	der, err := base64.StdEncoding.DecodeString(d.Certificate)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	d.parsedCert = cert
	return cert, nil
}

type regRequest struct {
	JoinType           int            `json:"JoinType"`
	DeviceID           string         `json:"DeviceId"`
	TargetDomain       string         `json:"TargetDomain"`
	DeviceType         string         `json:"DeviceType"`
	OSVersion          string         `json:"OSVersion"`
	CertificateRequest certReqPayload `json:"CertificateRequest"`
	Attributes         regAttributes  `json:"Attributes"`
}

type certReqPayload struct {
	Type string `json:"Type"`
	Data string `json:"Data"` // base64 PKCS#10 CSR
}

type regAttributes struct {
	ReuseDevice     string `json:"ReuseDevice"`
	ReturnClientSid string `json:"ReturnClientSid"`
}

type regResponse struct {
	Certificate struct {
		RawBody string `json:"RawBody"`
	} `json:"Certificate"`
}

// Register joins a new virtual device to Entra ID and returns the resulting
// device certificate and private key. accessToken must be valid for the
// device registration resource (urn:ms-drs:enterpriseregistration.windows.net).
func Register(ctx context.Context, accessToken, label, targetDomain, deviceType, osVersion string, joinType int) (*DeviceCert, error) {
	// Generate RSA-2048 key pair
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("key generation: %w", err)
	}

	deviceID := uuid.New().String()

	// Build PKCS#10 CSR
	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: deviceID,
		},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, privKey)
	if err != nil {
		return nil, fmt.Errorf("CSR creation: %w", err)
	}
	csrB64 := base64.StdEncoding.EncodeToString(csrDER)

	if deviceType == "" {
		deviceType = "Windows"
	}
	if osVersion == "" {
		osVersion = "10.0.19041.0"
	}

	payload := regRequest{
		JoinType:     joinType,
		DeviceID:     deviceID,
		TargetDomain: targetDomain,
		DeviceType:   deviceType,
		OSVersion:    osVersion,
		CertificateRequest: certReqPayload{
			Type: "pkcs10",
			Data: csrB64,
		},
		Attributes: regAttributes{
			ReuseDevice:     "false",
			ReturnClientSid: "true",
		},
	}

	bodyBytes, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, "POST", deviceRegEndpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.2210.133")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("registration request: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("device registration failed %d: %s", resp.StatusCode, string(respBody))
	}

	var regResp regResponse
	if err := json.Unmarshal(respBody, &regResp); err != nil {
		return nil, fmt.Errorf("parsing registration response: %w", err)
	}

	// Encode private key as PEM
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privKey),
	})

	return &DeviceCert{
		ID:           uuid.New().String(),
		Label:        label,
		DeviceID:     deviceID,
		JoinType:     joinType,
		Certificate:  regResp.Certificate.RawBody,
		PrivateKeyPEM: string(keyPEM),
		TargetDomain: targetDomain,
		CreatedAt:    time.Now().UTC(),
	}, nil
}
