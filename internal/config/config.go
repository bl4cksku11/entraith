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
	Host string `yaml:"host"`
	Port int    `yaml:"port"`
	TLS  bool   `yaml:"tls"`
}

type AuthConfig struct {
	SecretKey string `yaml:"secret_key"`
}

type CampaignConfig struct {
	// Microsoft Device Code flow settings
	TenantID     string `yaml:"tenant_id"`      // "common" or specific tenant
	ClientID     string `yaml:"client_id"`       // Azure App Client ID (use known public client IDs or your own)
	Scope        string `yaml:"scope"`           // e.g. "https://graph.microsoft.com/.default offline_access openid profile"
	PollInterval int    `yaml:"poll_interval"`   // seconds between polls, min 5
	PollTimeout  int    `yaml:"poll_timeout"`    // seconds total before expiry (usually 900)
}

type StorageConfig struct {
	ArtifactsPath string `yaml:"artifacts_path"`
	ExportsPath   string `yaml:"exports_path"`
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
	cfg.Storage.ArtifactsPath = kv["storage.artifacts_path"]
	cfg.Storage.ExportsPath = kv["storage.exports_path"]

	setDefaults(cfg)
	return cfg, nil
}

func setDefaults(cfg *Config) {
	if cfg.Server.Port == 0 {
		cfg.Server.Port = 8443
	}
	if cfg.Server.Host == "" {
		cfg.Server.Host = "127.0.0.1"
	}
	if cfg.Campaign.TenantID == "" {
		cfg.Campaign.TenantID = "common"
	}
	if cfg.Campaign.PollInterval == 0 {
		cfg.Campaign.PollInterval = 5
	}
	if cfg.Campaign.PollTimeout == 0 {
		cfg.Campaign.PollTimeout = 900
	}
	if cfg.Campaign.Scope == "" {
		cfg.Campaign.Scope = "https://graph.microsoft.com/.default offline_access openid profile"
	}
	if cfg.Storage.ArtifactsPath == "" {
		cfg.Storage.ArtifactsPath = "/opt/entraith/data/artifacts"
	}
	if cfg.Storage.ExportsPath == "" {
		cfg.Storage.ExportsPath = "/opt/entraith/data/exports"
	}
}
