package api

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/bl4cksku11/entraith/internal/campaigns"
	"github.com/bl4cksku11/entraith/internal/mailer"
	"github.com/bl4cksku11/entraith/internal/targets"
)

type Handler struct {
	Manager *campaigns.Manager
	Mailer  *mailer.Manager
}

func NewHandler(mgr *campaigns.Manager, mail *mailer.Manager) *Handler {
	return &Handler{Manager: mgr, Mailer: mail}
}

func (h *Handler) Routes() http.Handler {
	mux := http.NewServeMux()

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

	// Email sending
	mux.HandleFunc("POST /api/campaigns/{id}/send-emails", h.sendEmails)
	mux.HandleFunc("GET /api/campaigns/{id}/email-results", h.getEmailResults)

	// Export & delete
	mux.HandleFunc("GET /api/campaigns/{id}/export", h.exportCampaign)
	mux.HandleFunc("DELETE /api/campaigns/{id}", h.deleteCampaign)

	// SSE for real-time updates
	mux.HandleFunc("GET /api/campaigns/{id}/events", h.streamEvents)

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

	return mux
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
	if c.Engine == nil {
		writeJSON(w, 200, map[string]interface{}{"sessions": map[string]interface{}{}})
		return
	}
	writeJSON(w, 200, map[string]interface{}{"sessions": c.Engine.AllSessions()})
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

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			status, err := h.Manager.GetStatus(id)
			if err != nil {
				return
			}
			if c.Engine != nil {
				status["sessions"] = c.Engine.AllSessions()
			}
			data, err := json.Marshal(status)
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
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
