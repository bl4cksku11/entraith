package api

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// ─── Main-server webhook handler ─────────────────────────────────────────────

func (h *Handler) receiveWebhook(w http.ResponseWriter, r *http.Request) {
	ct := r.Header.Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		writeError(w, 415, "Content-Type must be application/json")
		return
	}

	var payload json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeError(w, 400, "invalid JSON body")
		return
	}

	if err := writeWebhookLogEntry(h.WebhookLogPath, r.RemoteAddr, payload); err != nil {
		writeError(w, 500, "failed to write log")
		return
	}

	writeJSON(w, 200, map[string]string{"status": "received"})
}

// ─── Shared log writer ────────────────────────────────────────────────────────

func writeWebhookLogEntry(logPath, remoteAddr string, payload json.RawMessage) error {
	if logPath == "" {
		logPath = "stream_monitor.log"
	}
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	entry := fmt.Sprintf("[%s] source=%s payload=%s\n",
		time.Now().UTC().Format(time.RFC3339),
		remoteAddr,
		string(payload),
	)
	_, err = f.WriteString(entry)
	return err
}

// ─── WebhookListener — standalone server on configurable port ────────────────

type WebhookEntry struct {
	Timestamp string `json:"timestamp"`
	Source    string `json:"source"`
	Payload   string `json:"payload"`
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
		ct := r.Header.Get("Content-Type")
		if !strings.Contains(ct, "application/json") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(415)
			w.Write([]byte(`{"error":"Content-Type must be application/json"}`))
			return
		}
		var payload json.RawMessage
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(400)
			w.Write([]byte(`{"error":"invalid JSON body"}`))
			return
		}
		writeWebhookLogEntry(logPath, r.RemoteAddr, payload)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write([]byte(`{"status":"received"}`))
	})

	srv := &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: mux,
	}
	wl.server = srv
	wl.port = port
	wl.running = true

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
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

// parseLogLine parses: [2024-01-01T00:00:00Z] source=1.2.3.4:5678 payload={...}
func parseLogLine(line string) WebhookEntry {
	var e WebhookEntry
	// timestamp between [ ]
	if i := strings.Index(line, "["); i >= 0 {
		if j := strings.Index(line, "]"); j > i {
			e.Timestamp = line[i+1 : j]
			line = strings.TrimSpace(line[j+1:])
		}
	}
	// source=
	if after, ok := strings.CutPrefix(line, "source="); ok {
		idx := strings.Index(after, " payload=")
		if idx >= 0 {
			e.Source = after[:idx]
			e.Payload = after[idx+len(" payload="):]
		} else {
			e.Source = after
		}
	} else {
		e.Payload = line
	}
	return e
}
