package main

import (
  "bufio"
  "bytes"
  "context"
  "crypto/sha256"
  "database/sql"
  "encoding/hex"
  "encoding/json"
  "fmt"
  "io"
  "log"
  "net"
  "net/http"
  "os"
  "os/exec"
  "os/signal"
  "regexp"
  "strings"
  "sync"
  "sync/atomic"
  "syscall"
  "time"

  "github.com/docker/docker/api/types/container"
  "github.com/docker/docker/client"
  "github.com/docker/docker/pkg/stdcopy"
  _ "github.com/mattn/go-sqlite3"
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

var (
  AppConfig    Config
  AppMetrics   Metrics
  BannedIPs    sync.Map
  PayloadCache sync.Map
  WhitelistMap map[string]bool
  CompRegex    *regexp.Regexp
  HttpClient   = &http.Client{Timeout: 1 * time.Second}
  DB           *sql.DB
)

func loadConfig() {
  file, err := os.ReadFile("/etc/sentinel/config.json")
  if err != nil {
    log.Fatalf("[FATAL] Config: %v", err)
  }
  if err := json.Unmarshal(file, &AppConfig); err != nil {
    log.Fatalf("[FATAL] JSON: %v", err)
  }
  WhitelistMap = make(map[string]bool)
  for _, ip := range AppConfig.WhitelistedIPs {
    WhitelistMap[ip] = true
  }
  CompRegex = regexp.MustCompile(AppConfig.RegexPattern)
  log.Printf("[INIT] Client: %s | Cible: %s", AppConfig.ClientName, AppConfig.TargetContainer)
}

func initDB() {
  var err error
  DB, err = sql.Open("sqlite3", AppConfig.DBPath)
  if err != nil {
    log.Fatalf("[FATAL] SQLite: %v", err)
  }
  q := `CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    ip TEXT, uri TEXT, engine TEXT, active BOOLEAN DEFAULT 1
  );`
  if _, err := DB.Exec(q); err != nil {
    log.Fatalf("[FATAL] Table: %v", err)
  }
}

func resetChain() {
  _ = exec.Command("iptables", "-F", "DOCKER-USER").Run()
  _ = exec.Command("iptables", "-A", "DOCKER-USER", "-j", "RETURN").Run()
  atomic.StoreInt64(&AppMetrics.ActiveBans, 0)
  log.Println("[KERNEL INIT] DOCKER-USER reinitialisee.")
}

func executeBan(ip, uri, engine string) {
  if exec.Command("iptables", "-C", "DOCKER-USER", "-s", ip, "-j", "DROP").Run() == nil {
    return
  }
  if err := exec.Command("iptables", "-I", "DOCKER-USER", "1", "-s", ip, "-j", "DROP").Run(); err != nil {
    BannedIPs.Delete(ip)
    return
  }
  atomic.AddInt64(&AppMetrics.ActiveBans, 1)
  _, _ = DB.Exec(`INSERT INTO events (ip, uri, engine, active) VALUES (?, ?, ?, 1)`, ip, uri, engine)
  log.Printf("[L3 BAN] IP %s radiee (Moteur: %s)", ip, engine)

  if AppConfig.BanDurationMinutes > 0 {
    time.AfterFunc(time.Duration(AppConfig.BanDurationMinutes)*time.Minute, func() {
      unbanIP(ip)
    })
  }
}

func unbanIP(ip string) {
  removed := false
  for exec.Command("iptables", "-D", "DOCKER-USER", "-s", ip, "-j", "DROP").Run() == nil {
    removed = true
  }
  if removed {
    if atomic.AddInt64(&AppMetrics.ActiveBans, -1) < 0 {
      atomic.StoreInt64(&AppMetrics.ActiveBans, 0)
    }
    log.Printf("[UNBAN] IP %s liberee.", ip)
  }
  _, _ = DB.Exec(`UPDATE events SET active = 0 WHERE ip = ?`, ip)
  BannedIPs.Delete(ip)
}

func processThreat(line string) {
  parts := strings.Split(strings.TrimSpace(line), " ")
  if len(parts) == 0 {
    return
  }
  parsed := net.ParseIP(parts[0])
  if parsed == nil {
    return
  }
  ip := parsed.String()
  if WhitelistMap[ip] {
    return
  }
  if _, loaded := BannedIPs.LoadOrStore(ip, time.Now()); loaded {
    return
  }

  uri := line
  if q1 := strings.Index(line, "\""); q1 != -1 {
    if q2 := strings.Index(line[q1+1:], "\""); q2 != -1 {
      uri = line[q1+1 : q1+1+q2]
    }
  }
  sum := sha256.Sum256([]byte(uri))
  hash := hex.EncodeToString(sum[:])

  if cached, ok := PayloadCache.Load(hash); ok {
    atomic.AddUint64(&AppMetrics.CacheHits, 1)
    if cached.(bool) {
      log.Printf("[CACHE HIT L2] Menace connue (%s).", ip)
      executeBan(ip, uri, "Cache SHA-256")
    } else {
      BannedIPs.Delete(ip)
    }
    return
  }

  atomic.AddUint64(&AppMetrics.LLMCalls, 1)
  reqData, _ := json.Marshal(map[string]any{
    "model":   AppConfig.LLMModel,
    "prompt":  fmt.Sprintf("WAF: '%s'. Exploit/Injection = MENACE. Sinon = SAIN. 1 mot:", uri),
    "stream":  false,
    "options": map[string]any{"num_predict": 5, "temperature": 0.0},
  })

  resp, err := HttpClient.Post(AppConfig.OllamaURL, "application/json", bytes.NewBuffer(reqData))
  if err != nil {
    log.Printf("[FALLBACK L2] Ollama HS (%v). Frappe heuristique activee.", err)
    PayloadCache.Store(hash, true)
    executeBan(ip, uri, "Heuristique L2")
    return
  }
  defer resp.Body.Close()

  body, _ := io.ReadAll(resp.Body)
  var out struct {
    Response string `json:"response"`
  }
  _ = json.Unmarshal(body, &out)

  ans := strings.ToUpper(strings.TrimSpace(out.Response))
  isThreat := ans == "" || strings.Contains(ans, "MENACE") || !strings.Contains(ans, "SAIN")
  PayloadCache.Store(hash, isThreat)

  if isThreat {
    executeBan(ip, uri, "Llama 3.2")
  } else {
    BannedIPs.Delete(ip)
  }
}

func monitor(ctx context.Context, cli *client.Client) {
  for {
    select {
    case <-ctx.Done():
      return
    default:
      opts := container.LogsOptions{ShowStdout: true, ShowStderr: true, Follow: true, Tail: "0"}
      out, err := cli.ContainerLogs(ctx, AppConfig.TargetContainer, opts)
      if err != nil {
        time.Sleep(3 * time.Second)
        continue
      }
      log.Printf("[L1] Ecoute stdcopy active sur %s", AppConfig.TargetContainer)
      pr, pw := io.Pipe()
      go func() {
        _, _ = stdcopy.StdCopy(pw, pw, out)
        pw.Close()
      }()
      sc := bufio.NewScanner(pr)
      for sc.Scan() {
        line := strings.TrimSpace(sc.Text())
        if line == "" {
          continue
        }
        atomic.AddUint64(&AppMetrics.LogsProcessed, 1)
        if CompRegex.MatchString(line) {
          atomic.AddUint64(&AppMetrics.RegexHits, 1)
          log.Printf("[L1 REGEX] Suspect: %s", line)
          go processThreat(line)
        }
      }
      out.Close()
      pr.Close()
      time.Sleep(2 * time.Second)
    }
  }
}

func auth(next http.HandlerFunc) http.HandlerFunc {
  return func(w http.ResponseWriter, r *http.Request) {
    tok := r.URL.Query().Get("token")
    if tok == "" {
      h := r.Header.Get("Authorization")
      if strings.HasPrefix(h, "Bearer ") {
        tok = strings.TrimPrefix(h, "Bearer ")
      }
    }
    if tok != AppConfig.APIKey {
      w.Header().Set("Content-Type", "application/json")
      w.WriteHeader(http.StatusUnauthorized)
      _, _ = w.Write([]byte(`{"error":"Unauthorized"}`))
      return
    }
    next.ServeHTTP(w, r)
  }
}

func main() {
  loadConfig()
  initDB()
  resetChain()

  ctx, cancel := context.WithCancel(context.Background())
  defer cancel()

  cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
  if err != nil {
    log.Fatalf("[FATAL] Docker: %v", err)
  }
  go monitor(ctx, cli)

  http.HandleFunc("/api/metrics", auth(func(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    rows, _ := DB.Query(`SELECT id, timestamp, ip, uri, engine, active FROM events ORDER BY id DESC LIMIT 50`)
    evts := []ThreatEvent{}
    for rows != nil && rows.Next() {
      var e ThreatEvent
      _ = rows.Scan(&e.ID, &e.Timestamp, &e.IP, &e.URI, &e.Engine, &e.Active)
      evts = append(evts, e)
    }
    if rows != nil {
      rows.Close()
    }
    _ = json.NewEncoder(w).Encode(map[string]any{
      "client":  AppConfig.ClientName,
      "status":  "OPERATIONAL",
      "metrics": AppMetrics,
      "events":  evts,
    })
  }))

  http.HandleFunc("/api/unban", auth(func(w http.ResponseWriter, r *http.Request) {
    ip := r.URL.Query().Get("ip")
    if net.ParseIP(ip) == nil {
      http.Error(w, `{"error":"Invalid IP"}`, http.StatusBadRequest)
      return
    }
    unbanIP(ip)
    w.Header().Set("Content-Type", "application/json")
    _, _ = w.Write([]byte(`{"status":"unbanned","ip":"` + ip + `"}`))
  }))

  go func() {
    log.Printf("[CONTROL PLANE V5.1] Actif sur http://%s", AppConfig.MetricsPort)
    _ = http.ListenAndServe(AppConfig.MetricsPort, nil)
  }()

  sigChan := make(chan os.Signal, 1)
  signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
  <-sigChan
  resetChain()
}
