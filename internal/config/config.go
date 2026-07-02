package config

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	Engagement EngagementConfig `yaml:"engagement"`
	Database   DatabaseConfig   `yaml:"database"`
	Server     ServerConfig     `yaml:"server"`
	Auth       AuthConfig       `yaml:"auth"`
	Campaign   CampaignConfig   `yaml:"campaign"`
	Storage    StorageConfig    `yaml:"storage"`
	Listener   ListenerConfig   `yaml:"listener"`
}

type EngagementConfig struct {
	ID            string `yaml:"id"`
	ClientCode    string `yaml:"client_code"`
	Operator      string `yaml:"operator"`
	RetentionDays int    `yaml:"retention_days"`
}

type DatabaseConfig struct {
	DSN string `yaml:"dsn"`
}

type ServerConfig struct {
	Host          string   `yaml:"host"`
	Port          int      `yaml:"port"`
	TLS           bool     `yaml:"tls"`            // terminate TLS natively (otherwise put a proxy in front)
	CertFile      string   `yaml:"cert_file"`     // PEM cert when tls = true
	KeyFile       string   `yaml:"key_file"`      // PEM key when tls = true
	SecureCookies bool     `yaml:"secure_cookies"` // mark session cookies Secure (default true)
	IPAllowlist   []string `yaml:"ip_allowlist"`  // CIDRs/IPs allowed to reach the operator console (empty = all)
}

type AuthConfig struct {
	SecretKey string `yaml:"secret_key"`
}

type CampaignConfig struct {
	// Microsoft Device Code flow settings
	TenantID     string `yaml:"tenant_id"`      // specific tenant GUID, or "organizations" for any work/school account
	ClientID     string `yaml:"client_id"`       // Azure App Client ID (use known public client IDs or your own)
	Scope        string `yaml:"scope"`           // e.g. "offline_access openid profile email"
	PollInterval int    `yaml:"poll_interval"`   // seconds between polls, min 5
	PollTimeout  int    `yaml:"poll_timeout"`    // seconds total before expiry (usually 900)
	CaptureV1    bool   `yaml:"capture_v1"`      // use v1 OAuth2 endpoints (resource= instead of scope=)
	RequireMFA   bool   `yaml:"require_mfa"`     // force MFA during device code auth
}

type StorageConfig struct {
	ArtifactsPath string `yaml:"artifacts_path"`
	ExportsPath   string `yaml:"exports_path"`
}

// ListenerConfig controls the standalone token-intake listener — a separate
// server that receives OAuth tokens pushed in from an AiTM proxy / phishing page
// / manual drop and ingests them into a campaign.
type ListenerConfig struct {
	TokenPort       int    `yaml:"token_port"`       // intake port (default 8000)
	TokenAutostart  bool   `yaml:"token_autostart"`  // start the listener at boot
	DefaultCampaign string `yaml:"default_campaign"` // campaign for tokens without an explicit campaign_id
}

func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening config: %w", err)
	}
	defer f.Close()

	kv := make(map[string]string)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		// Strip inline comments
		if idx := strings.Index(val, " #"); idx != -1 {
			val = strings.TrimSpace(val[:idx])
		}
		kv[key] = val
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}

	cfg := &Config{}
	cfg.Engagement.ID = kv["engagement.id"]
	cfg.Engagement.ClientCode = kv["engagement.client_code"]
	cfg.Engagement.Operator = kv["engagement.operator"]
	if v, err := strconv.Atoi(kv["engagement.retention_days"]); err == nil {
		cfg.Engagement.RetentionDays = v
	}
	cfg.Database.DSN = kv["database.dsn"]
	cfg.Server.Host = kv["server.host"]
	if v, err := strconv.Atoi(kv["server.port"]); err == nil {
		cfg.Server.Port = v
	}
	cfg.Server.CertFile = kv["server.cert_file"]
	cfg.Server.KeyFile = kv["server.key_file"]
	// Secure cookies default ON; only an explicit false/0/no disables them.
	cfg.Server.SecureCookies = true
	if v := strings.ToLower(kv["server.secure_cookies"]); v == "false" || v == "0" || v == "no" {
		cfg.Server.SecureCookies = false
	}
	if v := strings.ToLower(kv["server.tls"]); v == "true" || v == "1" || v == "yes" {
		cfg.Server.TLS = true
	}
	if v := strings.TrimSpace(kv["server.ip_allowlist"]); v != "" {
		for _, part := range strings.Split(v, ",") {
			if p := strings.TrimSpace(part); p != "" {
				cfg.Server.IPAllowlist = append(cfg.Server.IPAllowlist, p)
			}
		}
	}
	cfg.Auth.SecretKey = kv["auth.secret_key"]
	cfg.Campaign.TenantID = kv["campaign.tenant_id"]
	cfg.Campaign.ClientID = kv["campaign.client_id"]
	cfg.Campaign.Scope = kv["campaign.scope"]
	if v, err := strconv.Atoi(kv["campaign.poll_interval"]); err == nil {
		cfg.Campaign.PollInterval = v
	}
	if v, err := strconv.Atoi(kv["campaign.poll_timeout"]); err == nil {
		cfg.Campaign.PollTimeout = v
	}
	if v := strings.ToLower(kv["campaign.capture_v1"]); v == "true" || v == "1" || v == "yes" {
		cfg.Campaign.CaptureV1 = true
	}
	if v := strings.ToLower(kv["campaign.require_mfa"]); v == "true" || v == "1" || v == "yes" {
		cfg.Campaign.RequireMFA = true
	}
	cfg.Storage.ArtifactsPath = kv["storage.artifacts_path"]
	cfg.Storage.ExportsPath = kv["storage.exports_path"]

	if v, err := strconv.Atoi(kv["listener.token_port"]); err == nil {
		cfg.Listener.TokenPort = v
	}
	if v := strings.ToLower(kv["listener.token_autostart"]); v == "true" || v == "1" || v == "yes" {
		cfg.Listener.TokenAutostart = true
	}
	cfg.Listener.DefaultCampaign = kv["listener.default_campaign"]

	setDefaults(cfg)
	return cfg, nil
}

func setDefaults(cfg *Config) {
	if cfg.Server.Port == 0 {
		cfg.Server.Port = 80
	}
	if cfg.Server.Host == "" {
		cfg.Server.Host = "0.0.0.0"
	}
	if cfg.Campaign.TenantID == "" {
		cfg.Campaign.TenantID = "organizations"
	}
	if cfg.Campaign.PollInterval == 0 {
		cfg.Campaign.PollInterval = 5
	}
	if cfg.Campaign.PollTimeout == 0 {
		cfg.Campaign.PollTimeout = 900
	}
	if cfg.Campaign.Scope == "" {
		cfg.Campaign.Scope = "https://graph.microsoft.com/.default offline_access profile openid"
	}
	if cfg.Storage.ArtifactsPath == "" {
		cfg.Storage.ArtifactsPath = "/opt/entraith/data/artifacts"
	}
	if cfg.Storage.ExportsPath == "" {
		cfg.Storage.ExportsPath = "/opt/entraith/data/exports"
	}
	if cfg.Listener.TokenPort == 0 {
		cfg.Listener.TokenPort = 8000
	}
}
