package api

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// ─── Main-server webhook handler ─────────────────────────────────────────────

func (h *Handler) receiveWebhook(w http.ResponseWriter, r *http.Request) {
	body, format, httpErr := readWebhookBody(r)
	if httpErr != "" {
		writeError(w, 415, httpErr)
		return
	}
	if err := writeWebhookLogEntry(h.WebhookLogPath, r.RemoteAddr, r.Method, r.URL.Path, format, body); err != nil {
		writeError(w, 500, "failed to write log")
		return
	}
	writeJSON(w, 200, map[string]string{"status": "received"})
}

// ─── Shared helpers ───────────────────────────────────────────────────────────

// readWebhookBody reads the request body based on Content-Type.
//   - application/json     → validates JSON, returns format="json"
//   - application/json-raw → reads body as-is, returns format="raw"
// Returns (body, format, errMsg). errMsg is non-empty on bad Content-Type.
func readWebhookBody(r *http.Request) (body []byte, format string, errMsg string) {
	ct := r.Header.Get("Content-Type")
	switch {
	case strings.Contains(ct, "application/json-raw"):
		b, _ := io.ReadAll(r.Body)
		return b, "raw", ""
	case strings.Contains(ct, "application/json"):
		var msg json.RawMessage
		if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
			return nil, "", "invalid JSON body"
		}
		return []byte(msg), "json", ""
	default:
		return nil, "", "Content-Type must be application/json or application/json-raw"
	}
}

func writeWebhookLogEntry(logPath, remoteAddr, method, path, format string, body []byte) error {
	if logPath == "" {
		logPath = "stream_monitor.log"
	}
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	entry := fmt.Sprintf("[%s] source=%s method=%s path=%s format=%s payload=%s\n",
		time.Now().UTC().Format(time.RFC3339),
		remoteAddr, method, path, format, string(body),
	)
	_, err = f.WriteString(entry)
	return err
}

// ─── WebhookListener — standalone server on configurable port ────────────────

type WebhookEntry struct {
	Timestamp  string `json:"timestamp"`
	RemoteAddr string `json:"remote_addr"`
	Method     string `json:"method"`
	Path       string `json:"path"`
	Format     string `json:"format"` // "json" or "raw"
	Body       string `json:"body"`
}

type WebhookStatus struct {
	Running bool   `json:"running"`
	Port    int    `json:"port"`
	LogPath string `json:"log_path"`
	Entries int    `json:"entries"`
}

type WebhookListener struct {
	mu      sync.Mutex
	server  *http.Server
	port    int
	logPath string
	running bool
}

func NewWebhookListener(logPath string) *WebhookListener {
	return &WebhookListener{logPath: logPath}
}

func (wl *WebhookListener) Start(port int) error {
	wl.mu.Lock()
	defer wl.mu.Unlock()
	if wl.running {
		return fmt.Errorf("webhook listener already running on port %d", wl.port)
	}

	logPath := wl.logPath
	mux := http.NewServeMux()
	// Catch-all: accept POST to any path (e.g. /receive, /capture, /hook, etc.)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		body, format, errMsg := readWebhookBody(r)
		if errMsg != "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(415)
			fmt.Fprintf(w, `{"error":%q}`, errMsg)
			return
		}
		writeWebhookLogEntry(logPath, r.RemoteAddr, r.Method, r.URL.Path, format, body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write([]byte(`{"status":"received"}`))
	})

	// Bind the listener first so we can return an immediate error if the port
	// is already in use, rather than silently failing in a background goroutine.
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return fmt.Errorf("port %d unavailable: %w", port, err)
	}

	srv := &http.Server{Handler: mux}
	wl.server = srv
	wl.port = port
	wl.running = true

	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			wl.mu.Lock()
			wl.running = false
			wl.mu.Unlock()
		}
	}()

	return nil
}

func (wl *WebhookListener) Stop() error {
	wl.mu.Lock()
	defer wl.mu.Unlock()
	if !wl.running {
		return fmt.Errorf("webhook listener is not running")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := wl.server.Shutdown(ctx)
	wl.running = false
	wl.server = nil
	return err
}

func (wl *WebhookListener) Status() WebhookStatus {
	wl.mu.Lock()
	defer wl.mu.Unlock()
	return WebhookStatus{
		Running: wl.running,
		Port:    wl.port,
		LogPath: wl.logPath,
		Entries: countLogEntries(wl.logPath),
	}
}

func (wl *WebhookListener) GetLogs(n int) []WebhookEntry {
	return readLogTail(wl.logPath, n)
}

// ─── Log helpers ──────────────────────────────────────────────────────────────

func countLogEntries(path string) int {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()
	count := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if sc.Text() != "" {
			count++
		}
	}
	return count
}

func readLogTail(path string, n int) []WebhookEntry {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		if t := sc.Text(); t != "" {
			lines = append(lines, t)
		}
	}

	if n > 0 && len(lines) > n {
		lines = lines[len(lines)-n:]
	}

	entries := make([]WebhookEntry, 0, len(lines))
	for _, line := range lines {
		e := parseLogLine(line)
		entries = append(entries, e)
	}
	return entries
}

// parseLogLine parses: [ts] source=IP method=POST path=/foo payload={...}
func parseLogLine(line string) WebhookEntry {
	var e WebhookEntry
	// timestamp between [ ]
	if i := strings.Index(line, "["); i >= 0 {
		if j := strings.Index(line, "]"); j > i {
			e.Timestamp = line[i+1 : j]
			line = strings.TrimSpace(line[j+1:])
		}
	}
	if v, rest, ok := cutField(line, "source="); ok {
		e.RemoteAddr = v
		line = rest
	}
	if v, rest, ok := cutField(line, "method="); ok {
		e.Method = v
		line = rest
	}
	if v, rest, ok := cutField(line, "path="); ok {
		e.Path = v
		line = rest
	}
	if v, rest, ok := cutField(line, "format="); ok {
		e.Format = v
		line = rest
	}
	if after, ok := strings.CutPrefix(strings.TrimSpace(line), "payload="); ok {
		e.Body = after
	}
	return e
}

// cutField extracts the value after key up to the next space-separated key=value pair.
func cutField(line, key string) (value, rest string, ok bool) {
	after, found := strings.CutPrefix(strings.TrimSpace(line), key)
	if !found {
		return "", line, false
	}
	// value ends at the next " word=" boundary
	idx := strings.Index(after, " ")
	if idx < 0 {
		return after, "", true
	}
	return after[:idx], strings.TrimSpace(after[idx:]), true
}
