package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/bl4cksku11/entraith/internal/api"
	"github.com/bl4cksku11/entraith/internal/auth"
	"github.com/bl4cksku11/entraith/internal/campaigns"
	"github.com/bl4cksku11/entraith/internal/config"
	"github.com/bl4cksku11/entraith/internal/mailer"
	"github.com/bl4cksku11/entraith/internal/store"
	"github.com/bl4cksku11/entraith/internal/web"
)

// pageGuard validates the session cookie server-side before serving a protected
// HTML page. If the cookie is missing, invalid, or expired the browser is
// redirected to /login with a ?next= parameter so the user lands back on the
// right page after authenticating.
func pageGuard(db *store.Store, html string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session")
		if err != nil || cookie.Value == "" {
			redirectToLogin(w, r)
			return
		}
		sess, err := db.GetSession(cookie.Value)
		if err != nil || sess == nil || time.Now().After(sess.ExpiresAt) {
			// Expired or unknown session — clear the stale cookie
			http.SetCookie(w, &http.Cookie{
				Name:     "session",
				Value:    "",
				Path:     "/",
				MaxAge:   -1,
				HttpOnly: true,
				SameSite: http.SameSiteStrictMode,
			})
			redirectToLogin(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		// Prevent caching of authenticated pages
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Write([]byte(html))
	}
}

func redirectToLogin(w http.ResponseWriter, r *http.Request) {
	target := "/login?next=" + url.QueryEscape(r.URL.RequestURI())
	http.Redirect(w, r, target, http.StatusFound)
}

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
	case "reset-admin":
		runResetAdmin()
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

	// Generate admin user on first run
	if count, err := db.CountUsers(); err == nil && count == 0 {
		password := auth.GeneratePassword(16)
		salt := auth.GenerateSalt()
		hash := auth.HashPassword(password, salt)
		if err := db.CreateUser("user-admin", "admin", hash, salt); err != nil {
			log.Fatalf("Failed to create admin user: %v", err)
		}
		log.Printf("╔══════════════════════════════════════════════╗")
		log.Printf("║      FIRST RUN — ADMIN CREDENTIALS           ║")
		log.Printf("║  Username : admin                            ║")
		log.Printf("║  Password : %-32s ║", password)
		log.Printf("╚══════════════════════════════════════════════╝")
	}

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
	apiHandler := api.NewHandler(mgr, mailMgr, webhookLogPath, db)

	// Main router
	mux := http.NewServeMux()

	// Login page — public, no session required
	mux.HandleFunc("GET /login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
		w.Write([]byte(web.LoginHTML))
	})

	// Protected pages — server-side session guard redirects to /login if unauthenticated
	mux.HandleFunc("/", pageGuard(db, web.DashboardHTML))
	mux.HandleFunc("GET /tools", pageGuard(db, web.ToolsHTML))
	mux.HandleFunc("GET /infra", pageGuard(db, web.InfraHTML))

	// API routes
	mux.Handle("/api/", apiHandler.Routes())

	// Webhook listener control
	mux.Handle("/webhook/", apiHandler.Routes())

	// QR phishing — two-phase flow to defeat email security scanners.
	// GET  serves an inert JS page; POST /confirm is the real trigger.
	qrGet, qrConfirm := apiHandler.QRScanHandler()
	mux.HandleFunc("GET /qr/{token}", qrGet)
	mux.HandleFunc("POST /qr/{token}/confirm", qrConfirm)

	// Intune phishing — single-page OAuth login with ms-appx-web:// capture
	mux.HandleFunc("GET /intune/{token}", apiHandler.HandleIntuneLanding())

	// Webhook / telemetry receiver
	mux.Handle("/receive", apiHandler.Routes())

	// Native Broker Interop — public endpoint for URI capture
	mux.HandleFunc("POST /capture", apiHandler.CaptureBroker())

	// Intune capture — public endpoint for ms-appx-web:// capture from landing page
	mux.HandleFunc("POST /intune/capture", apiHandler.CaptureIntune)

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

func runResetAdmin() {
	fs := flag.NewFlagSet("reset-admin", flag.ExitOnError)
	cfgPath := fs.String("config", "", "path to config")
	fs.Parse(subArgs())
	resolvedCfg := resolveConfig(fs, cfgPath)
	if resolvedCfg == "" {
		fmt.Fprintf(os.Stderr, "error: config file required\n")
		fmt.Fprintf(os.Stderr, "usage: entraith reset-admin <config>\n")
		os.Exit(1)
	}

	cfg, err := config.Load(resolvedCfg)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	dataPath := filepath.Dir(cfg.Storage.ArtifactsPath)
	dbPath := filepath.Join(dataPath, "entraith.db")
	db, err := store.New(dbPath)
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	user, err := db.GetUserByUsername("admin")
	if err != nil || user == nil {
		log.Fatalf("Admin user not found — run 'entraith server' first to create it")
	}

	newPassword := auth.GeneratePassword(16)
	newSalt := auth.GenerateSalt()
	newHash := auth.HashPassword(newPassword, newSalt)

	if err := db.UpdateUserPassword("admin", newHash, newSalt); err != nil {
		log.Fatalf("Failed to reset password: %v", err)
	}

	log.Printf("╔══════════════════════════════════════════════╗")
	log.Printf("║         ADMIN PASSWORD RESET                ║")
	log.Printf("║  Username : admin                            ║")
	log.Printf("║  Password : %-32s ║", newPassword)
	log.Printf("╚══════════════════════════════════════════════╝")
}
