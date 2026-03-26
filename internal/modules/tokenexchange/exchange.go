// Package tokenexchange provides OAuth2 token exchange operations against
// Microsoft identity endpoints. Supports both v1.0 and v2.0 protocols,
// custom resources/scopes, and client_id substitution.
package tokenexchange

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	v1Endpoint = "https://login.microsoftonline.com/%s/oauth2/token?api-version=1.0"
	v2Endpoint = "https://login.microsoftonline.com/%s/oauth2/v2.0/token"
	oidcMeta   = "https://login.microsoftonline.com/%s/.well-known/openid-configuration"
)

// TokenPair holds the result of a token exchange.
type TokenPair struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	TokenType    string    `json:"token_type"`
	ExpiresIn    int       `json:"expires_in"`
	Scope        string    `json:"scope"`
	Resource     string    `json:"resource"`
	ObtainedAt   time.Time `json:"obtained_at"`
}

type exchangeError struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// Exchange exchanges a refresh token for an access token targeting a specific
// resource or scope. Set useV1=true for the legacy v1.0 endpoint (uses "resource"
// parameter), false for v2.0 (uses "scope").
func Exchange(ctx context.Context, tenantID, clientID, refreshToken, resource, scope string, useV1 bool) (*TokenPair, error) {
	if tenantID == "" {
		tenantID = "organizations"
	}
	var endpoint string
	if useV1 {
		endpoint = fmt.Sprintf(v1Endpoint, tenantID)
	} else {
		endpoint = fmt.Sprintf(v2Endpoint, tenantID)
	}

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("client_id", clientID)
	form.Set("refresh_token", refreshToken)
	if useV1 && resource != "" {
		form.Set("resource", resource)
	} else if !useV1 && scope != "" {
		form.Set("scope", scope)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.2210.133")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token exchange request failed: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		var ee exchangeError
		json.Unmarshal(body, &ee)
		return nil, fmt.Errorf("%s: %s", ee.Error, ee.ErrorDescription)
	}

	var result TokenPair
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parsing token response: %w", err)
	}
	result.ObtainedAt = time.Now().UTC()
	if useV1 {
		result.Resource = resource
	}
	return &result, nil
}

// LookupTenantID resolves a domain name (e.g. "contoso.com") to its Entra
// tenant GUID by querying the OIDC metadata endpoint.
func LookupTenantID(ctx context.Context, domain string) (string, error) {
	url := fmt.Sprintf(oidcMeta, domain)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("lookup request failed: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	var meta struct {
		Issuer string `json:"issuer"`
	}
	if err := json.Unmarshal(body, &meta); err != nil || meta.Issuer == "" {
		return "", fmt.Errorf("could not parse OIDC metadata for domain %s", domain)
	}
	// issuer = "https://sts.windows.net/<tenant-guid>/"
	parts := strings.Split(strings.TrimRight(meta.Issuer, "/"), "/")
	if len(parts) == 0 {
		return "", fmt.Errorf("unexpected issuer format: %s", meta.Issuer)
	}
	return parts[len(parts)-1], nil
}

// KnownResources maps friendly names to resource/scope values usable in Exchange.
var KnownResources = map[string]struct{ V1Resource, V2Scope string }{
	"graph":          {"https://graph.microsoft.com", "https://graph.microsoft.com/.default offline_access profile openid"},
	"outlook":        {"https://outlook.office.com", "https://outlook.office.com/.default offline_access"},
	"teams":          {"https://api.spaces.skype.com", "https://api.spaces.skype.com/.default offline_access"},
	"azure":          {"https://management.azure.com", "https://management.azure.com/.default offline_access"},
	"devicereg":      {"urn:ms-drs:enterpriseregistration.windows.net", "urn:ms-drs:enterpriseregistration.windows.net/.default"},
	"mfa_registration": {"19db86c3-b2b9-44cc-b339-36da233a3be2", "19db86c3-b2b9-44cc-b339-36da233a3be2/.default"},
	"keyvault":       {"https://vault.azure.net", "https://vault.azure.net/.default offline_access"},
	"storage":        {"https://storage.azure.com", "https://storage.azure.com/.default offline_access"},
}
