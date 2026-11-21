package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"strings"
)

type mockFirewall struct {
	mu     sync.Mutex
	banned map[string]bool
}

func newMockFirewall() *mockFirewall {
	return &mockFirewall{banned: make(map[string]bool)}
}

func (m *mockFirewall) Reset() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	clear(m.banned)
	return nil
}

func (m *mockFirewall) Ban(ip string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.banned[ip] = true
	return nil
}

func (m *mockFirewall) Unban(ip string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, exists := m.banned[ip]
	delete(m.banned, ip)
	return exists, nil
}

func (m *mockFirewall) isBanned(ip string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.banned[ip]
}

func newTestAgent(t *testing.T, ollamaURL string) (*Agent, *mockFirewall) {
	t.Helper()

	db, err := initDB(":memory:")
	if err != nil {
		t.Fatalf("initDB(:memory:) a échoué: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	fw := newMockFirewall()
	cfg := Config{
		ClientName:         "test-client",
		TargetContainer:    "traefik-proxy",
		OllamaURL:          ollamaURL,
		LLMModel:           "llama3.2",
		BanDurationMinutes: 0,
		MetricsPort:        "127.0.0.1:9090",
		APIKey:             "super-secret-test-key",
		DBPath:             ":memory:",
		WhitelistedIPs:     []string{"127.0.0.1", "10.0.0.5"},
		RegexPattern:       `(?i)(union\s+select|[;&|]|%3B|%26|%7C)\s*(id|whoami|wget|curl|cat)|(\/|%2F)etc(\/|%2F)passwd|(\.\.%2F|\.\.\/)`,
	}

	agent, err := NewAgent(cfg, db, fw)
	if err != nil {
		t.Fatalf("NewAgent a échoué: %v", err)
	}
	// Timeout réduit pour accélérer le test fail-closed.
	agent.httpClient = &http.Client{Timeout: 200 * time.Millisecond}
	return agent, fw
}

func TestExtractIPAndURI(t *testing.T) {
	tests := []struct {
		name    string
		line    string
		wantIP  string
		wantURI string
		wantOK  bool
	}{
		{
			name:    "log Traefik CLF valide",
			line:    `203.0.113.7 - - [20/Nov/2026:12:00:00 +0000] "GET /ping?ip=127.0.0.1;id HTTP/1.1" 200 42`,
			wantIP:  "203.0.113.7",
			wantURI: "GET /ping?ip=127.0.0.1;id HTTP/1.1",
			wantOK:  true,
		},
		{
			name:    "ligne sans guillemets",
			line:    `203.0.113.8 GET /etc/passwd`,
			wantIP:  "203.0.113.8",
			wantURI: "203.0.113.8 GET /etc/passwd",
			wantOK:  true,
		},
		{
			name:   "IPv6 ignorée car incompatible iptables",
			line:   `2001:db8::1 - - [20/Nov/2026:12:00:00 +0000] "GET /etc/passwd HTTP/1.1" 404 0`,
			wantOK: false,
		},
		{
			name:   "ligne vide",
			line:   "   ",
			wantOK: false,
		},
		{
			name:   "première colonne non IP",
			line:   `not-an-ip - - "GET / HTTP/1.1"`,
			wantOK: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ip, uri, ok := extractIPAndURI(tc.line)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, attendu %v", ok, tc.wantOK)
			}
			if !tc.wantOK {
				return
			}
			if ip != tc.wantIP || uri != tc.wantURI {
				t.Fatalf("obtenu (%q, %q), attendu (%q, %q)", ip, uri, tc.wantIP, tc.wantURI)
			}
		})
	}
}

func TestNewAgentValidation(t *testing.T) {
	db, err := initDB(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	if _, err := NewAgent(Config{RegexPattern: "test"}, db, newMockFirewall()); err == nil {
		t.Fatal("NewAgent aurait dû refuser une api_key vide")
	}

	if _, err := NewAgent(Config{APIKey: "secret", RegexPattern: "[invalide"}, db, newMockFirewall()); err == nil {
		t.Fatal("NewAgent aurait dû refuser une regex invalide")
	}
}

func TestWhitelistIgnored(t *testing.T) {
	var llmCalls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		llmCalls.Add(1)
		_, _ = w.Write([]byte(`{"response":"MENACE"}`))
	}))
	defer srv.Close()

	agent, fw := newTestAgent(t, srv.URL)
	agent.processThreat(context.Background(), `10.0.0.5 - - "GET /etc/passwd HTTP/1.1" 404`)

	if fw.isBanned("10.0.0.5") {
		t.Fatal("une IP en liste blanche ne doit jamais être bannie")
	}
	if llmCalls.Load() != 0 {
		t.Fatalf("Ollama ne doit pas être appelé pour une IP whitelistée (appels=%d)", llmCalls.Load())
	}
}

func TestLLMThreatAndCacheHit(t *testing.T) {
	var llmCalls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		llmCalls.Add(1)
		_, _ = w.Write([]byte(`{"response":"MENACE"}`))
	}))
	defer srv.Close()

	agent, fw := newTestAgent(t, srv.URL)

	// 1er appel : interroge Ollama et met le verdict en cache.
	agent.processThreat(context.Background(), `203.0.113.10 - - "GET /ping?ip=1;id HTTP/1.1" 200`)
	if !fw.isBanned("203.0.113.10") {
		t.Fatal("203.0.113.10 aurait dû être bannie")
	}

	// 2e appel : même payload depuis une autre IP -> doit passer par le cache SHA-256.
	agent.processThreat(context.Background(), `203.0.113.11 - - "GET /ping?ip=1;id HTTP/1.1" 200`)
	if !fw.isBanned("203.0.113.11") {
		t.Fatal("203.0.113.11 aurait dû être bannie via le cache")
	}

	if llmCalls.Load() != 1 {
		t.Fatalf("nombre d'appels Ollama = %d, attendu 1", llmCalls.Load())
	}
	snap := agent.SnapshotMetrics()
	if snap.LLMCalls != 1 || snap.CacheHits != 1 || snap.ActiveBans != 2 {
		t.Fatalf("métriques inattendues: %+v", snap)
	}
}

func TestLLMBenignDoesNotBan(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"response":"SAIN"}`))
	}))
	defer srv.Close()

	agent, fw := newTestAgent(t, srv.URL)
	agent.processThreat(context.Background(), `203.0.113.20 - - "GET /search?q=1&id=42 HTTP/1.1" 200`)

	if fw.isBanned("203.0.113.20") {
		t.Fatal("une requête jugée SAIN ne doit pas être bannie")
	}
	if _, stillTracked := agent.bannedIPs.Load("203.0.113.20"); stillTracked {
		t.Fatal("l'IP doit être retirée de bannedIPs après un verdict SAIN")
	}
}

func TestFailClosedOnOllamaTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(500 * time.Millisecond):
		}
	}))
	defer srv.Close()

	agent, fw := newTestAgent(t, srv.URL)
	agent.processThreat(context.Background(), `203.0.113.30 - - "GET /etc/passwd HTTP/1.1" 404`)

	if !fw.isBanned("203.0.113.30") {
		t.Fatal("en cas de timeout Ollama, l'agent doit bannir en mode fail-closed")
	}

	var engine string
	if err := agent.db.QueryRow(`SELECT engine FROM events WHERE ip = ?`, "203.0.113.30").Scan(&engine); err != nil {
		t.Fatalf("événement non enregistré en base: %v", err)
	}
	if engine != "Heuristique L2" {
		t.Fatalf("moteur = %q, attendu %q", engine, "Heuristique L2")
	}
}

func TestHTTPAuthAndEndpoints(t *testing.T) {
	agent, fw := newTestAgent(t, "http://127.0.0.1:0")
	agent.executeBan("203.0.113.99", "GET /etc/passwd HTTP/1.1", "llama3.2")

	handler := agent.Routes()

	// 1. Sans authentification -> 401
	req := httptest.NewRequest(http.MethodGet, "/api/metrics", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("sans token: statut = %d, attendu 401", rec.Code)
	}

	// 2. Avec Bearer valide -> 200 et métriques cohérentes
	req = httptest.NewRequest(http.MethodGet, "/api/metrics", nil)
	req.Header.Set("Authorization", "Bearer super-secret-test-key")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("avec token valide: statut = %d, attendu 200", rec.Code)
	}

	var payload struct {
		Status  string          `json:"status"`
		Metrics MetricsSnapshot `json:"metrics"`
		Events  []ThreatEvent   `json:"events"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("JSON /api/metrics invalide: %v", err)
	}
	if payload.Status != "OPERATIONAL" || payload.Metrics.ActiveBans != 1 || len(payload.Events) != 1 {
		t.Fatalf("contenu /api/metrics inattendu: %+v", payload)
	}

	// 3. /api/unban avec IP invalide -> 400
	req = httptest.NewRequest(http.MethodGet, "/api/unban?ip=invalide", nil)
	req.Header.Set("Authorization", "Bearer super-secret-test-key")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("IP invalide: statut = %d, attendu 400", rec.Code)
	}

	// 4. /api/unban avec IP valide -> 200 et règle levée
	req = httptest.NewRequest(http.MethodGet, "/api/unban?ip=203.0.113.99", nil)
	req.Header.Set("Authorization", "Bearer super-secret-test-key")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("unban valide: statut = %d, attendu 200", rec.Code)
	}
	if fw.isBanned("203.0.113.99") {
		t.Fatal("203.0.113.99 aurait dû être débannie")
	}
	if agent.SnapshotMetrics().ActiveBans != 0 {
		t.Fatalf("ActiveBans = %d, attendu 0", agent.SnapshotMetrics().ActiveBans)
	}
}

func TestConcurrentProcessThreatAndMetrics(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"response":"MENACE"}`))
	}))
	defer srv.Close()

	agent, _ := newTestAgent(t, srv.URL)
	handler := agent.Routes()

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(2)
		go func(idx int) {
			defer wg.Done()
			line := fmt.Sprintf(`198.51.100.%d - - "GET /ping?ip=1;id HTTP/1.1" 200`, idx+1)
			agent.processThreat(context.Background(), line)
		}(i)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodGet, "/api/metrics", nil)
			req.Header.Set("Authorization", "Bearer super-secret-test-key")
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
		}()
	}
	wg.Wait()
}

func TestPrometheusMetricsEndpoint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"response":"MENACE"}`))
	}))
	defer srv.Close()

	agent, _ := newTestAgent(t, srv.URL)
	agent.processThreat(context.Background(), `203.0.113.55 - - "GET /ping?ip=1;id HTTP/1.1" 200`)

	handler := agent.Routes()

	// Sans token -> 401
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("/metrics sans token: statut = %d, attendu 401", rec.Code)
	}

	// Avec Bearer valide -> 200 et métriques Prometheus présentes
	req = httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer super-secret-test-key")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("/metrics avec token: statut = %d, attendu 200", rec.Code)
	}

	body := rec.Body.String()
	for _, want := range []string{
		`dockban_decisions_total{engine="llm",verdict="threat"} 1`,
		`dockban_active_bans 1`,
		`dockban_llm_duration_seconds_count 1`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("métrique attendue absente (%s) dans:\n%s", want, body)
		}
	}
}
