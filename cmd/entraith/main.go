package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/bl4cksku11/entraith/internal/api"
	"github.com/bl4cksku11/entraith/internal/campaigns"
	"github.com/bl4cksku11/entraith/internal/config"
	"github.com/bl4cksku11/entraith/internal/mailer"
	"github.com/bl4cksku11/entraith/internal/store"
	"github.com/bl4cksku11/entraith/internal/web"
)

func usage() {
	fmt.Fprintf(os.Stderr, "Usage:\n")
	fmt.Fprintf(os.Stderr, "  entraith server   <config>          start the operator console\n")
	fmt.Fprintf(os.Stderr, "  entraith validate <config>          validate config file\n")
	fmt.Fprintf(os.Stderr, "  entraith version                    print version\n")
	fmt.Fprintf(os.Stderr, "\nFlags (alternative to positional config):\n")
	fmt.Fprintf(os.Stderr, "  --config <path>                     path to engagement config file\n")
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "server":
		runServer()
	case "validate":
		runValidate()
	case "version":
		fmt.Println("entraith v0.2.0")
	default:
		usage()
		os.Exit(1)
	}
}

func subArgs() []string {
	if len(os.Args) > 2 {
		return os.Args[2:]
	}
	return nil
}

// resolveConfig returns the config path from --config flag or first positional arg.
// Returns "" if neither was provided.
func resolveConfig(fs *flag.FlagSet, cfgPath *string) string {
	if *cfgPath != "" {
		return *cfgPath
	}
	if args := fs.Args(); len(args) > 0 {
		return args[0]
	}
	return ""
}

func runServer() {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	cfgPath := fs.String("config", "", "path to engagement config file")
	fs.Parse(subArgs())
	resolvedCfg := resolveConfig(fs, cfgPath)
	if resolvedCfg == "" {
		fmt.Fprintf(os.Stderr, "error: config file required\n")
		fmt.Fprintf(os.Stderr, "usage: entraith server <config>\n")
		os.Exit(1)
	}

	cfg, err := config.Load(resolvedCfg)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Ensure storage directories exist
	dataPath := filepath.Dir(cfg.Storage.ArtifactsPath)
	os.MkdirAll(dataPath, 0700)
	os.MkdirAll(cfg.Storage.ArtifactsPath, 0700)
	os.MkdirAll(cfg.Storage.ExportsPath, 0700)

	// Open SQLite database
	dbPath := filepath.Join(dataPath, "entraith.db")
	db, err := store.New(dbPath)
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	// Build mailer manager and wire persistence
	mailMgr := mailer.NewManager()
	mailMgr.SetPersistence(
		func(p *mailer.SenderProfile) {
			db.UpsertSenderProfile(store.SenderProfileRow{
				ID:          p.ID,
				Name:        p.Name,
				Host:        p.Host,
				Port:        p.Port,
				Username:    p.Username,
				Password:    p.Password,
				FromAddress: p.FromAddress,
				FromName:    p.FromName,
				ImplicitTLS: p.ImplicitTLS,
				CreatedAt:   p.CreatedAt,
			})
		},
		func(id string) { db.DeleteSenderProfile(id) },
		func(t *mailer.EmailTemplate) {
			db.UpsertEmailTemplate(store.EmailTemplateRow{
				ID:            t.ID,
				Name:          t.Name,
				Subject:       t.Subject,
				HTMLBody:      t.HTMLBody,
				TextBody:      t.TextBody,
				RedirectorURL: t.RedirectorURL,
				CreatedAt:     t.CreatedAt,
			})
		},
		func(id string) { db.DeleteEmailTemplate(id) },
	)

	// Load mailer state from database
	profileRows, err := db.LoadSenderProfiles()
	if err != nil {
		log.Fatalf("Failed to load sender profiles: %v", err)
	}
	profiles := make([]mailer.SenderProfile, len(profileRows))
	for i, r := range profileRows {
		profiles[i] = mailer.SenderProfile{
			ID: r.ID, Name: r.Name, Host: r.Host, Port: r.Port,
			Username: r.Username, Password: r.Password,
			FromAddress: r.FromAddress, FromName: r.FromName,
			ImplicitTLS: r.ImplicitTLS, CreatedAt: r.CreatedAt,
		}
	}
	mailMgr.LoadProfiles(profiles)

	templateRows, err := db.LoadEmailTemplates()
	if err != nil {
		log.Fatalf("Failed to load email templates: %v", err)
	}
	templates := make([]mailer.EmailTemplate, len(templateRows))
	for i, r := range templateRows {
		templates[i] = mailer.EmailTemplate{
			ID: r.ID, Name: r.Name, Subject: r.Subject,
			HTMLBody: r.HTMLBody, TextBody: r.TextBody,
			RedirectorURL: r.RedirectorURL, CreatedAt: r.CreatedAt,
		}
	}
	mailMgr.LoadTemplates(templates)

	// Build campaign manager and restore persisted state
	mgr := campaigns.NewManager(
		cfg.Campaign.TenantID,
		cfg.Campaign.ClientID,
		cfg.Campaign.Scope,
		cfg.Campaign.PollInterval,
		cfg.Storage.ArtifactsPath,
		cfg.Storage.ExportsPath,
		db,
	)
	if err := mgr.Load(); err != nil {
		log.Fatalf("Failed to load campaign state: %v", err)
	}

	// Build API handler
	webhookLogPath := filepath.Join(cfg.Storage.ArtifactsPath, "stream_monitor.log")
	apiHandler := api.NewHandler(mgr, mailMgr, webhookLogPath)

	// Main router
	mux := http.NewServeMux()

	// Dashboard
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(web.DashboardHTML))
	})

	// API routes
	mux.Handle("/api/", apiHandler.Routes())

	// Webhook / telemetry receiver
	mux.Handle("/receive", apiHandler.Routes())

	// Health check
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status":      "ok",
			"engagement":  cfg.Engagement.ID,
			"client_code": cfg.Engagement.ClientCode,
			"operator":    cfg.Engagement.Operator,
		})
	})

	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	log.Printf("╔════════════════════════════════════════╗")
	log.Printf("║          ENTRAITH Operator Tool        ║")
	log.Printf("╚════════════════════════════════════════╝")
	log.Printf("Engagement : %s", cfg.Engagement.ID)
	log.Printf("Operator   : %s", cfg.Engagement.Operator)
	log.Printf("Tenant     : %s", cfg.Campaign.TenantID)
	log.Printf("Client ID  : %s", cfg.Campaign.ClientID)
	log.Printf("Database   : %s", dbPath)
	log.Printf("Listening  : http://%s", addr)
	log.Printf("Webhook    : POST http://%s/receive  → %s", addr, webhookLogPath)

	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}

func runValidate() {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	cfgPath := fs.String("config", "", "path to config")
	fs.Parse(subArgs())
	resolvedCfg := resolveConfig(fs, cfgPath)
	if resolvedCfg == "" {
		fmt.Fprintf(os.Stderr, "error: config file required\n")
		fmt.Fprintf(os.Stderr, "usage: entraith validate <config>\n")
		os.Exit(1)
	}

	cfg, err := config.Load(resolvedCfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Config validation passed:")
	fmt.Printf("  Engagement ID : %s\n", cfg.Engagement.ID)
	fmt.Printf("  Client Code   : %s\n", cfg.Engagement.ClientCode)
	fmt.Printf("  Tenant ID     : %s\n", cfg.Campaign.TenantID)
	fmt.Printf("  Client ID     : %s\n", cfg.Campaign.ClientID)
	fmt.Printf("  Scope         : %s\n", cfg.Campaign.Scope)
	fmt.Printf("  Poll Interval : %ds\n", cfg.Campaign.PollInterval)
	fmt.Printf("  Artifacts     : %s\n", cfg.Storage.ArtifactsPath)
}
