package main

import (
    "bytes"
    "context"
    "encoding/json"
    "fmt"
    "io"
    "log"
    "net/http"
    "os/exec"
    "regexp"
    "strings"

    "github.com/docker/docker/api/types/container"
    "github.com/docker/docker/client"
)

type OllamaRequest struct {
    Model  string `json:"model"`
    Prompt string `json:"prompt"`
    Stream bool   `json:"stream"`
}

type OllamaResponse struct {
    Response string `json:"response"`
}

func monitorTraefik(ctx context.Context, cli *client.Client, alertChan chan<- string) {
    options := container.LogsOptions{ShowStdout: true, ShowStderr: true, Follow: true, Tail: "0"}
    out, err := cli.ContainerLogs(ctx, "traefik-proxy", options)
    if err != nil {
        log.Fatalf("Erreur Traefik: %v", err)
    }
    defer out.Close()

    regex := regexp.MustCompile(`(?i)(union\s+select|[;&]|%3B)\s*id|\/etc\/passwd|%2Fetc%2Fpasswd`)
    buf := make([]byte, 4096)

    for {
        n, err := out.Read(buf)
        if n > 8 {
            logChunk := string(buf[8:n])
            fmt.Print("[SOCKET NETTOYÉ] " + logChunk)
            if regex.MatchString(logChunk) {
                alertChan <- logChunk
            }
        }
        if err != nil {
            break
        }
    }
}

func verifyPayloadWithLLM(payload string) {
    prompt := fmt.Sprintf(`Tu es un WAF. Analyse ce log brut : "%s". 
    RÈGLES : Décode les URL. Injections de commandes (id, wget) ou SQL = attaques. 
    Réponds STRICTEMENT et UNIQUEMENT "MENACE" ou "SAIN". Aucun autre mot.`, payload)

    reqBody, _ := json.Marshal(OllamaRequest{
        Model:  "llama3.2",
        Prompt: prompt,
        Stream: false,
    })

    resp, err := http.Post("http://localhost:11434/api/generate", "application/json", bytes.NewBuffer(reqBody))
    if err != nil {
        log.Printf("[CIRCUIT BREAKER] IA locale hors ligne : %v\n", err)
        return
    }
    defer resp.Body.Close()

    body, _ := io.ReadAll(resp.Body)
    var llmResp OllamaResponse
    json.Unmarshal(body, &llmResp)

    decision := strings.TrimSpace(strings.ToUpper(llmResp.Response))
    fmt.Printf("\n[DEBUG Llama 3.2] -> '%s'\n", llmResp.Response)

    if strings.Contains(decision, "MENACE") {
        fmt.Printf("[☠️ NIVEAU 2 - LOCAL] Validation confirmée. Jugement: MENACE\n")
        
        // Phase 3 : Extraction IP et Frappe Iptables
        attackerIP := strings.Split(payload, " ")[0]
        fmt.Printf("[NIVEAU 3] Armement Iptables contre l'IP : %s\n", attackerIP)

        cmd := exec.Command("sudo", "iptables", "-I", "DOCKER-USER", "1", "-s", attackerIP, "-j", "DROP")
        
        if err := cmd.Run(); err != nil {
            fmt.Printf("[ÉCHEC KERNEL] Droits root insuffisants : %v\n", err)
        } else {
            fmt.Printf("[🛡️ EXECUTION COMPLETE] L'entité %s est radiée du réseau.\n", attackerIP)
        }
    } else {
        fmt.Printf("[✅ NIVEAU 2 - LOCAL] Faux positif. Jugement: %s\n", decision)
    }
}

func main() {
    ctx := context.Background()
    cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
    if err != nil {
        log.Fatalf("Erreur Docker: %v", err)
    }

    alertChan := make(chan string)
    fmt.Println("[SENTINEL-ZERO] V3.0 - Boucle complète armée (L1 Regex -> L2 Llama -> L3 Iptables).")

    go monitorTraefik(ctx, cli, alertChan)

    for threat := range alertChan {
        fmt.Printf("\n[⚠️ NIVEAU 1 - REGEX] Suspect intercepté: %s\n", threat)
        fmt.Println("[NIVEAU 2] Transmission asynchrone à Llama 3.2...")
        go verifyPayloadWithLLM(threat)
    }
}
