package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

const (
	maxCacheEntries       = 10000
	maxConcurrentAnalyses = 16
	maxLLMResponseBytes   = 1 << 20 // 1 MiB
)

type Config struct {
	ClientName         string   `json:"client_name"`
	TargetContainer    string   `json:"target_container"`
	OllamaURL          string   `json:"ollama_url"`
	LLMModel           string   `json:"llm_model"`
	DiscordWebhook     string   `json:"discord_webhook"`
	BanDurationMinutes int      `json:"ban_duration_minutes"`
	MetricsPort        string   `json:"metrics_port"`
	APIKey             string   `json:"api_key"`
	DBPath             string   `json:"db_path"`
	WhitelistedIPs     []string `json:"whitelisted_ips"`
	RegexPattern       string   `json:"regex_pattern"`
}

type Metrics struct {
	LogsProcessed atomic.Uint64
	RegexHits     atomic.Uint64
	CacheHits     atomic.Uint64
	LLMCalls      atomic.Uint64
	ActiveBans    atomic.Int64
}

type MetricsSnapshot struct {
	LogsProcessed uint64 `json:"logs_processed"`
	RegexHits     uint64 `json:"regex_hits"`
	CacheHits     uint64 `json:"cache_hits"`
	LLMCalls      uint64 `json:"llm_calls"`
	ActiveBans    int64  `json:"active_bans"`
}

type ThreatEvent struct {
	ID        int    `json:"id"`
	Timestamp string `json:"timestamp"`
	IP        string `json:"ip"`
	URI       string `json:"uri"`
	Engine    string `json:"engine"`
	Active    bool   `json:"active"`
}

type Agent struct {
	cfg        Config
	db         *sql.DB
	fw         Firewall
	regex      *regexp.Regexp
	whitelist  map[string]bool
	httpClient *http.Client
	metrics    Metrics

	bannedIPs sync.Map
	cacheMu   sync.RWMutex
	cache     map[string]bool
	sem       chan struct{}
}

func initDB(dbPath string) (*sql.DB, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("ouverture SQLite: %w", err)
	}
	// SQLite ne supporte qu'un seul écrivain simultané : évite les erreurs "database is locked"
	// et garantit que ":memory:" dans les tests partage la même base.
	db.SetMaxOpenConns(1)

	const schema = `CREATE TABLE IF NOT EXISTS events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
		ip TEXT NOT NULL,
		uri TEXT NOT NULL,
		engine TEXT NOT NULL,
		active BOOLEAN DEFAULT 1
	);`
	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("création table events: %w", err)
	}
	return db, nil
}

func NewAgent(cfg Config, db *sql.DB, fw Firewall) (*Agent, error) {
	if strings.TrimSpace(cfg.APIKey) == "" {
		return nil, errors.New("api_key obligatoire et non vide dans la configuration")
	}
	if strings.TrimSpace(cfg.RegexPattern) == "" {
		return nil, errors.New("regex_pattern obligatoire dans la configuration")
	}
	if db == nil {
		return nil, errors.New("connexion SQLite nil")
	}
	if fw == nil {
		return nil, errors.New("implémentation Firewall nil")
	}

	compRegex, err := regexp.Compile(cfg.RegexPattern)
	if err != nil {
		return nil, fmt.Errorf("regex invalide: %w", err)
	}

	whitelist := make(map[string]bool, len(cfg.WhitelistedIPs))
	for _, rawIP := range cfg.WhitelistedIPs {
		if parsed := net.ParseIP(strings.TrimSpace(rawIP)); parsed != nil {
			whitelist[parsed.String()] = true
		}
	}

	return &Agent{
		cfg:        cfg,
		db:         db,
		fw:         fw,
		regex:      compRegex,
		whitelist:  whitelist,
		httpClient: &http.Client{Timeout: 1 * time.Second},
		cache:      make(map[string]bool),
		sem:        make(chan struct{}, maxConcurrentAnalyses),
	}, nil
}

func (a *Agent) ResetFirewall() error {
	if err := a.fw.Reset(); err != nil {
		return err
	}
	a.metrics.ActiveBans.Store(0)
	log.Println("[KERNEL] Chaîne DOCKER-USER réinitialisée.")
	return nil
}

func (a *Agent) SnapshotMetrics() MetricsSnapshot {
	return MetricsSnapshot{
		LogsProcessed: a.metrics.LogsProcessed.Load(),
		RegexHits:     a.metrics.RegexHits.Load(),
		CacheHits:     a.metrics.CacheHits.Load(),
		LLMCalls:      a.metrics.LLMCalls.Load(),
		ActiveBans:    a.metrics.ActiveBans.Load(),
	}
}

func (a *Agent) getCache(hash string) (bool, bool) {
	a.cacheMu.RLock()
	defer a.cacheMu.RUnlock()
	val, ok := a.cache[hash]
	return val, ok
}

func (a *Agent) setCache(hash string, isThreat bool) {
	a.cacheMu.Lock()
	defer a.cacheMu.Unlock()
	if len(a.cache) >= maxCacheEntries {
		// Réinitialisation simple pour borner la RAM sans dépendance externe.
		clear(a.cache)
	}
	a.cache[hash] = isThreat
}

// extractIPAndURI extrait l'IPv4 source (1re colonne CLF) et la requête HTTP entre guillemets.
func extractIPAndURI(line string) (string, string, bool) {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return "", "", false
	}

	parsed := net.ParseIP(fields[0])
	if parsed == nil || parsed.To4() == nil {
		// iptables ne gère que l'IPv4 (IPv6 nécessiterait ip6tables).
		return "", "", false
	}

	uri := strings.TrimSpace(line)
	if q1 := strings.Index(line, "\""); q1 != -1 {
		if q2 := strings.Index(line[q1+1:], "\""); q2 != -1 {
			uri = line[q1+1 : q1+1+q2]
		}
	}

	return parsed.String(), uri, true
}

func (a *Agent) HandleLogLine(ctx context.Context, line string) {
	line = strings.TrimSpace(line)
	if line == "" {
		return
	}

	a.metrics.LogsProcessed.Add(1)
	if !a.regex.MatchString(line) {
		return
	}

	a.metrics.RegexHits.Add(1)
	log.Printf("[L1 REGEX] Ligne suspecte: %s", line)

	select {
	case a.sem <- struct{}{}:
		go func() {
			defer func() { <-a.sem }()
			a.processThreat(ctx, line)
		}()
	default:
		log.Println("[WARN] Concurrence d'analyse saturée, ligne ignorée.")
	}
}

func (a *Agent) processThreat(ctx context.Context, line string) {
	ip, uri, ok := extractIPAndURI(line)
	if !ok {
		return
	}
	if a.whitelist[ip] {
		return
	}
	if _, loaded := a.bannedIPs.LoadOrStore(ip, time.Now()); loaded {
		return
	}

	sum := sha256.Sum256([]byte(uri))
	hash := hex.EncodeToString(sum[:])

	if isThreat, found := a.getCache(hash); found {
		a.metrics.CacheHits.Add(1)
		if isThreat {
			log.Printf("[CACHE HIT L2] Menace connue (%s).", ip)
			a.executeBan(ip, uri, "Cache SHA-256")
		} else {
			a.bannedIPs.Delete(ip)
		}
		return
	}

	a.metrics.LLMCalls.Add(1)
	isThreat, err := a.classifyWithLLM(ctx, uri)
	if err != nil {
		log.Printf("[FALLBACK L2] Ollama indisponible (%v), blocage heuristique appliqué.", err)
		// On ne met pas en cache un fallback d'erreur pour éviter d'empoisonner le cache.
		a.executeBan(ip, uri, "Heuristique L2")
		return
	}

	a.setCache(hash, isThreat)
	if isThreat {
		engine := a.cfg.LLMModel
		if engine == "" {
			engine = "LLM"
		}
		a.executeBan(ip, uri, engine)
	} else {
		a.bannedIPs.Delete(ip)
	}
}

func (a *Agent) classifyWithLLM(ctx context.Context, uri string) (bool, error) {
	reqData, err := json.Marshal(map[string]any{
		"model":   a.cfg.LLMModel,
		"prompt":  fmt.Sprintf("WAF: '%s'. Exploit/Injection = MENACE. Sinon = SAIN. 1 mot:", uri),
		"stream":  false,
		"options": map[string]any{"num_predict": 5, "temperature": 0.0},
	})
	if err != nil {
		return true, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.cfg.OllamaURL, bytes.NewReader(reqData))
	if err != nil {
		return true, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return true, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return true, fmt.Errorf("statut HTTP Ollama inattendu: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxLLMResponseBytes))
	if err != nil {
		return true, err
	}

	var out struct {
		Response string `json:"response"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return true, err
	}

	ans := strings.ToUpper(strings.TrimSpace(out.Response))
	isThreat := ans == "" || strings.Contains(ans, "MENACE") || !strings.Contains(ans, "SAIN")
	return isThreat, nil
}

func (a *Agent) executeBan(ip, uri, engine string) {
	if err := a.fw.Ban(ip); err != nil {
		log.Printf("[ERR L3] Échec ban IP %s: %v", ip, err)
		a.bannedIPs.Delete(ip)
		return
	}

	a.metrics.ActiveBans.Add(1)
	if _, err := a.db.Exec(
		`INSERT INTO events (ip, uri, engine, active) VALUES (?, ?, ?, 1)`,
		ip, uri, engine,
	); err != nil {
		log.Printf("[ERR DB] Insertion événement échouée: %v", err)
	}
	log.Printf("[L3 BAN] IP %s bloquée (moteur: %s)", ip, engine)

	if a.cfg.BanDurationMinutes > 0 {
		time.AfterFunc(time.Duration(a.cfg.BanDurationMinutes)*time.Minute, func() {
			a.unbanIP(ip)
		})
	}
}

func (a *Agent) unbanIP(ip string) {
	removed, err := a.fw.Unban(ip)
	if err != nil {
		log.Printf("[ERR UNBAN] Échec suppression règle pour %s: %v", ip, err)
	}

	if removed {
		for {
			cur := a.metrics.ActiveBans.Load()
			if cur <= 0 {
				break
			}
			if a.metrics.ActiveBans.CompareAndSwap(cur, cur-1) {
				break
			}
		}
		log.Printf("[UNBAN] IP %s libérée.", ip)
	}

	if _, err := a.db.Exec(`UPDATE events SET active = 0 WHERE ip = ?`, ip); err != nil {
		log.Printf("[ERR DB] Mise à jour unban échouée: %v", err)
	}
	a.bannedIPs.Delete(ip)
}

func (a *Agent) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/metrics", a.authMiddleware(a.handleMetrics))
	mux.HandleFunc("/api/unban", a.authMiddleware(a.handleUnban))
	return mux
}

func (a *Agent) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := r.URL.Query().Get("token")
		if tok == "" {
			h := r.Header.Get("Authorization")
			if strings.HasPrefix(h, "Bearer ") {
				tok = strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
			}
		}

		if subtle.ConstantTimeCompare([]byte(tok), []byte(a.cfg.APIKey)) != 1 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"Unauthorized"}`))
			return
		}
		next.ServeHTTP(w, r)
	}
}

func (a *Agent) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		_, _ = w.Write([]byte(`{"error":"Method not allowed"}`))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	rows, err := a.db.Query(
		`SELECT id, timestamp, ip, uri, engine, active FROM events ORDER BY id DESC LIMIT 50`,
	)
	evts := make([]ThreatEvent, 0)
	if err != nil {
		log.Printf("[ERR DB] Lecture événements échouée: %v", err)
	} else {
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var e ThreatEvent
			if scanErr := rows.Scan(&e.ID, &e.Timestamp, &e.IP, &e.URI, &e.Engine, &e.Active); scanErr == nil {
				evts = append(evts, e)
			}
		}
	}

	_ = json.NewEncoder(w).Encode(map[string]any{
		"client":  a.cfg.ClientName,
		"status":  "OPERATIONAL",
		"metrics": a.SnapshotMetrics(),
		"events":  evts,
	})
}

func (a *Agent) handleUnban(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		_, _ = w.Write([]byte(`{"error":"Method not allowed"}`))
		return
	}

	rawIP := strings.TrimSpace(r.URL.Query().Get("ip"))
	parsed := net.ParseIP(rawIP)
	if parsed == nil || parsed.To4() == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"Invalid IPv4 address"}`))
		return
	}

	ip := parsed.String()
	a.unbanIP(ip)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status": "unbanned",
		"ip":     ip,
	})
}
