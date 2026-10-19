package main

import (
	"bytes"
	"context"
	"crypto/sha256"
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
)

// --- STRUCTURES DE CONFIGURATION & MÉTRIQUES ---

type Config struct {
	ClientName         string   `json:"client_name"`
	TargetContainer    string   `json:"target_container"`
	OllamaURL          string   `json:"ollama_url"`
	LLMModel           string   `json:"llm_model"`
	DiscordWebhook     string   `json:"discord_webhook"`
	BanDurationMinutes int      `json:"ban_duration_minutes"`
	MetricsPort        string   `json:"metrics_port"`
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

type OllamaRequest struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
	Stream bool   `json:"stream"`
}

type OllamaResponse struct {
	Response string `json:"response"`
}

type DiscordMessage struct {
	Embeds []Embed `json:"embeds"`
}

type Embed struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Color       int    `json:"color"`
	Timestamp   string `json:"timestamp"`
}

// --- ÉTAT GLOBAL THREAD-SAFE ---

var (
	AppConfig     Config
	AppMetrics    Metrics
	BannedIPs     sync.Map // map[string]time.Time (Anti-flood Iptables)
	PayloadCache  sync.Map // map[string]bool      (Cache sémantique SHA-256 : true = MENACE)
	WhitelistMap  map[string]bool
	CompiledRegex *regexp.Regexp
	HttpClient    = &http.Client{Timeout: 30 * time.Second}
)

// --- INITIALISATION ---

func loadConfig(path string) {
	file, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("[FATAL] Lecture configuration impossible (%s) : %v", path, err)
	}
	if err := json.Unmarshal(file, &AppConfig); err != nil {
		log.Fatalf("[FATAL] JSON invalide dans %s : %v", path, err)
	}

	WhitelistMap = make(map[string]bool)
	for _, ip := range AppConfig.WhitelistedIPs {
		WhitelistMap[ip] = true
	}

	var regexErr error
	CompiledRegex, regexErr = regexp.Compile(AppConfig.RegexPattern)
	if regexErr != nil {
		log.Fatalf("[FATAL] Compilation Regex échouée : %v", regexErr)
	}

	log.Printf("[INIT] Client: %s | Modèle: %s | Cible: %s", AppConfig.ClientName, AppConfig.LLMModel, AppConfig.TargetContainer)
}

// --- UTILITAIRES DE SÉCURITÉ ---

func extractValidIP(logLine string) (string, bool) {
	parts := strings.Split(strings.TrimSpace(logLine), " ")
	if len(parts) == 0 {
		return "", false
	}
	rawIP := parts[0]
	parsedIP := net.ParseIP(rawIP)
	if parsedIP == nil {
		return "", false
	}
	return parsedIP.String(), true
}

func extractRequestURI(logLine string) string {
	// Extrait uniquement la requête HTTP (ex: "GET /ping?ip=... HTTP/1.1") pour le cache sémantique
	firstQuote := strings.Index(logLine, "\"")
	if firstQuote == -1 {
		return logLine
	}
	secondQuote := strings.Index(logLine[firstQuote+1:], "\"")
	if secondQuote == -1 {
		return logLine
	}
	return logLine[firstQuote+1 : firstQuote+1+secondQuote]
}

func hashString(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// --- COUCHE 1 : INTERCEPTION SOCKET DOCKER ---

func monitorContainer(ctx context.Context, cli *client.Client, alertChan chan<- string) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			options := container.LogsOptions{ShowStdout: true, ShowStderr: true, Follow: true, Tail: "0"}
			out, err := cli.ContainerLogs(ctx, AppConfig.TargetContainer, options)
			if err != nil {
				log.Printf("[ERREUR L1] Connexion conteneur %s échouée : %v. Nouvel essai dans 5s...", AppConfig.TargetContainer, err)
				time.Sleep(5 * time.Second)
				continue
			}

			log.Printf("[L1] Écoute active sur le socket de %s", AppConfig.TargetContainer)
			buf := make([]byte, 8192)

			for {
				n, err := out.Read(buf)
				if n > 8 {
					logChunk := string(buf[8:n])
					lines := strings.Split(logChunk, "\n")
					for _, line := range lines {
						line = strings.TrimSpace(line)
						if line == "" {
							continue
						}
						atomic.AddUint64(&AppMetrics.LogsProcessed, 1)

						if CompiledRegex.MatchString(line) {
							atomic.AddUint64(&AppMetrics.RegexHits, 1)
							alertChan <- line
						}
					}
				}
				if err != nil {
					if err != io.EOF {
						log.Printf("[WARN L1] Flux interrompu : %v", err)
					}
					out.Close()
					break
				}
			}
			time.Sleep(2 * time.Second)
		}
	}
}

// --- COUCHE 2 : ANALYSE COGNITIVE & CACHE SÉMANTIQUE ---

func processThreat(logLine string) {
	attackerIP, valid := extractValidIP(logLine)
	if !valid {
		log.Printf("[WARN] IP invalide ignorée dans le log : %s", logLine)
		return
	}

	if WhitelistMap[attackerIP] {
		log.Printf("[WHITELIST] IP protégée ignorée : %s", attackerIP)
		return
	}

	// Déduplication immédiate : si l'IP est déjà bannie ou en cours de traitement, on ignore
	if _, alreadyBanned := BannedIPs.LoadOrStore(attackerIP, time.Now()); alreadyBanned {
		return
	}

	requestURI := extractRequestURI(logLine)
	payloadHash := hashString(requestURI)

	// 1. Vérification du Cache Sémantique (0 latence, 0 appel LLM)
	if cachedDecision, found := PayloadCache.Load(payloadHash); found {
		atomic.AddUint64(&AppMetrics.CacheHits, 1)
		if cachedDecision.(bool) {
			log.Printf("[⚡ CACHE HIT L2] Attaque connue détectée (%s). Frappe immédiate.", attackerIP)
			executeKernelBan(attackerIP, requestURI, "Cache Sémantique (SHA-256)")
		} else {
			BannedIPs.Delete(attackerIP)
		}
		return
	}

	// 2. Appel LLM Local (Ollama)
	atomic.AddUint64(&AppMetrics.LLMCalls, 1)
	prompt := fmt.Sprintf(`Tu es un WAF réseau strict. Analyse cette requête HTTP : "%s".
RÈGLES : Décode l'URL. Injections de commandes (id, whoami, wget, curl), Path Traversal (/etc/passwd) ou SQLi = MENACE.
Réponds UNIQUEMENT par le mot "MENACE" ou "SAIN".`, requestURI)

	reqBody, _ := json.Marshal(OllamaRequest{
		Model:  AppConfig.LLMModel,
		Prompt: prompt,
		Stream: false,
	})

	resp, err := HttpClient.Post(AppConfig.OllamaURL, "application/json", bytes.NewBuffer(reqBody))
	if err != nil {
		log.Printf("[CIRCUIT BREAKER L2] Ollama injoignable : %v", err)
		BannedIPs.Delete(attackerIP) // Libère le verrou en cas de panne IA
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var llmResp OllamaResponse
	if err := json.Unmarshal(body, &llmResp); err != nil {
		BannedIPs.Delete(attackerIP)
		return
	}

	decision := strings.ToUpper(llmResp.Response)
	isThreat := strings.Contains(decision, "MENACE")

	// Enregistrement dans le cache sémantique pour les futures requêtes
	PayloadCache.Store(payloadHash, isThreat)

	if isThreat {
		log.Printf("[☠️ L2 CONFIRMÉ] Jugement IA : MENACE pour %s", attackerIP)
		executeKernelBan(attackerIP, requestURI, fmt.Sprintf("IA Locale (%s)", AppConfig.LLMModel))
	} else {
		log.Printf("[✅ L2 SAIN] Faux positif écarté pour %s", attackerIP)
		BannedIPs.Delete(attackerIP)
	}
}

// --- COUCHE 3 : FRAPPE KERNEL IPTABLES & TTL ---

func executeKernelBan(ip string, uri string, engine string) {
	// Vérifie l'idempotence (ne pas insérer si la règle existe déjà dans le noyau)
	checkCmd := exec.Command("sudo", "iptables", "-C", "DOCKER-USER", "-s", ip, "-j", "DROP")
	if err := checkCmd.Run(); err == nil {
		log.Printf("[L3] L'IP %s est déjà présente dans DOCKER-USER.", ip)
		return
	}

	insertCmd := exec.Command("sudo", "iptables", "-I", "DOCKER-USER", "1", "-s", ip, "-j", "DROP")
	if err := insertCmd.Run(); err != nil {
		log.Printf("[ERREUR KERNEL L3] Échec iptables pour %s : %v", ip, err)
		BannedIPs.Delete(ip)
		return
	}

	atomic.AddInt64(&AppMetrics.ActiveBans, 1)
	log.Printf("[🛡️ L3 EXÉCUTÉ] Entité %s radiée (Moteur: %s).", ip, engine)

	go notifyDiscord(ip, uri, engine)

	// Programmation de l'Auto-Unban (TTL) si configuré (> 0)
	if AppConfig.BanDurationMinutes > 0 {
		duration := time.Duration(AppConfig.BanDurationMinutes) * time.Minute
		time.AfterFunc(duration, func() {
			unbanIP(ip)
		})
	}
}

func unbanIP(ip string) {
	delCmd := exec.Command("sudo", "iptables", "-D", "DOCKER-USER", "-s", ip, "-j", "DROP")
	if err := delCmd.Run(); err == nil {
		atomic.AddInt64(&AppMetrics.ActiveBans, -1)
		log.Printf("[♻️ TTL EXPIRÉ] L'entité %s a été retirée de DOCKER-USER.", ip)
	}
	BannedIPs.Delete(ip)
}

// --- OBSERVABILITÉ & API B2B ---

func notifyDiscord(ip string, uri string, engine string) {
	if AppConfig.DiscordWebhook == "" || strings.Contains(AppConfig.DiscordWebhook, "TON_LIEN") {
		return
	}

	msg := DiscordMessage{
		Embeds: []Embed{
			{
				Title: "🚨 SENTINEL-ZERO : MENACE NEUTRALISÉE",
				Description: fmt.Sprintf(
					"**Client :** `%s`\n**IP Hostile :** `%s`\n**Payload :** `%s`\n**Validation :** `%s`\n**Sanction :** `DROP (DOCKER-USER)`\n**TTL :** `%d min`",
					AppConfig.ClientName, ip, uri, engine, AppConfig.BanDurationMinutes,
				),
				Color:     16711680,
				Timestamp: time.Now().Format(time.RFC3339),
			},
		},
	}

	body, _ := json.Marshal(msg)
	_, err := HttpClient.Post(AppConfig.DiscordWebhook, "application/json", bytes.NewBuffer(body))
	if err != nil {
		log.Printf("[WARN DISCORD] Échec envoi webhook : %v", err)
	}
}

func startMetricsServer() {
	http.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		data := map[string]interface{}{
			"client":  AppConfig.ClientName,
			"status":  "OPERATIONAL",
			"metrics": AppMetrics,
		}
		json.NewEncoder(w).Encode(data)
	})
	log.Printf("[API B2B] Télémétrie exposée sur http://%s/metrics", AppConfig.MetricsPort)
	if err := http.ListenAndServe(AppConfig.MetricsPort, nil); err != nil {
		log.Printf("[WARN API] Serveur métriques arrêté : %v", err)
	}
}

// --- ORCHESTRATEUR PRINCIPAL ---

func main() {
	loadConfig("/etc/sentinel/config.json")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Gestion de l'arrêt propre (Systemd SIGTERM / Ctrl+C)
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		log.Fatalf("[FATAL] Initialisation client Docker échouée : %v", err)
	}

	go startMetricsServer()

	alertChan := make(chan string, 1000)
	go monitorContainer(ctx, cli, alertChan)

	log.Println("[SENTINEL-ZERO V4.0] Système Enterprise actif.")

	for {
		select {
		case threatLine := <-alertChan:
			go processThreat(threatLine)
		case sig := <-sigChan:
			log.Printf("[SHUTDOWN] Signal %v reçu. Arrêt propre de l'agent...", sig)
			cancel()
			time.Sleep(1 * time.Second)
			return
		}
	}
}
