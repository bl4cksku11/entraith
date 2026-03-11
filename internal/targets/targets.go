package targets

import (
	"crypto/rand"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

// Target represents a single campaign recipient
type Target struct {
	ID          string    `json:"id"`
	Email       string    `json:"email"`
	DisplayName string    `json:"display_name"`
	Department  string    `json:"department"`
	Region      string    `json:"region"`
	Group       string    `json:"group"`
	CustomField string    `json:"custom_field"`
	ImportedAt  time.Time `json:"imported_at"`
}

// Store is an in-memory target store for the engagement
type Store struct {
	mu      sync.RWMutex
	targets map[string]*Target // keyed by ID
	byEmail map[string]*Target // keyed by email (lowercase)
}

func NewStore() *Store {
	return &Store{
		targets: make(map[string]*Target),
		byEmail: make(map[string]*Target),
	}
}

func generateID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func (s *Store) Add(t *Target) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	email := strings.ToLower(strings.TrimSpace(t.Email))
	if email == "" {
		return fmt.Errorf("target email cannot be empty")
	}
	if _, exists := s.byEmail[email]; exists {
		return fmt.Errorf("duplicate target email: %s", email)
	}
	if t.ID == "" {
		t.ID = generateID()
	}
	t.Email = email
	if t.ImportedAt.IsZero() {
		t.ImportedAt = time.Now().UTC()
	}
	s.targets[t.ID] = t
	s.byEmail[email] = t
	return nil
}

func (s *Store) GetByID(id string) (*Target, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.targets[id]
	return t, ok
}

func (s *Store) GetByEmail(email string) (*Target, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.byEmail[strings.ToLower(email)]
	return t, ok
}

func (s *Store) All() []*Target {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Target, 0, len(s.targets))
	for _, t := range s.targets {
		out = append(out, t)
	}
	return out
}

func (s *Store) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.targets)
}

// ImportCSV reads a CSV and populates the store.
// Expected columns (header row required): email, display_name, department, region, group, custom_field
// Only "email" is required; others are optional.
func ImportCSV(r io.Reader, store *Store) (imported int, skipped int, errors []string) {
	cr := csv.NewReader(r)
	cr.TrimLeadingSpace = true

	headers, err := cr.Read()
	if err != nil {
		errors = append(errors, fmt.Sprintf("reading header row: %v", err))
		return
	}

	// normalize headers
	colIdx := make(map[string]int)
	for i, h := range headers {
		colIdx[strings.ToLower(strings.TrimSpace(h))] = i
	}

	emailIdx, ok := colIdx["email"]
	if !ok {
		errors = append(errors, "CSV missing required 'email' column")
		return
	}

	lineNum := 1
	for {
		lineNum++
		row, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			errors = append(errors, fmt.Sprintf("line %d: %v", lineNum, err))
			skipped++
			continue
		}

		cell := func(name string) string {
			idx, ok := colIdx[name]
			if !ok || idx >= len(row) {
				return ""
			}
			return strings.TrimSpace(row[idx])
		}

		t := &Target{
			Email:       strings.TrimSpace(row[emailIdx]),
			DisplayName: cell("display_name"),
			Department:  cell("department"),
			Region:      cell("region"),
			Group:       cell("group"),
			CustomField: cell("custom_field"),
		}

		if err := store.Add(t); err != nil {
			errors = append(errors, fmt.Sprintf("line %d (%s): %v", lineNum, t.Email, err))
			skipped++
			continue
		}
		imported++
	}
	return
}
