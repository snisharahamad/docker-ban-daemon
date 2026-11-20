package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
)

func loadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("lecture %s: %w", path, err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parsing JSON: %w", err)
	}
	return cfg, nil
}

func monitorDockerLogs(ctx context.Context, cli *client.Client, agent *Agent) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		opts := container.LogsOptions{
			ShowStdout: true,
			ShowStderr: true,
			Follow:     true,
			Tail:       "0",
		}
		out, err := cli.ContainerLogs(ctx, agent.cfg.TargetContainer, opts)
		if err != nil {
			log.Printf("[L1] Conteneur %s indisponible (%v), nouvelle tentative dans 3s...", agent.cfg.TargetContainer, err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(3 * time.Second):
				continue
			}
		}

		log.Printf("[L1] Écoute des logs active sur %s", agent.cfg.TargetContainer)
		pr, pw := io.Pipe()
		go func() {
			_, _ = stdcopy.StdCopy(pw, pw, out)
			_ = pw.Close()
		}()

		sc := bufio.NewScanner(pr)
		for sc.Scan() {
			agent.HandleLogLine(ctx, sc.Text())
		}

		_ = out.Close()
		_ = pr.Close()

		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
}

func main() {
	configPath := flag.String("config", "/etc/dockban/config.json", "Chemin vers le fichier de configuration JSON")
	flag.Parse()

	cfg, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("[FATAL] Config: %v", err)
	}

	db, err := initDB(cfg.DBPath)
	if err != nil {
		log.Fatalf("[FATAL] SQLite: %v", err)
	}
	defer func() { _ = db.Close() }()

	agent, err := NewAgent(cfg, db, &IPTablesFirewall{})
	if err != nil {
		log.Fatalf("[FATAL] Agent: %v", err)
	}
	log.Printf("[INIT] Client: %s | Cible: %s", cfg.ClientName, cfg.TargetContainer)

	if err := agent.ResetFirewall(); err != nil {
		log.Fatalf("[FATAL] Réinitialisation iptables: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		log.Fatalf("[FATAL] Docker: %v", err)
	}
	defer func() { _ = cli.Close() }()

	go monitorDockerLogs(ctx, cli, agent)

	srv := &http.Server{
		Addr:              cfg.MetricsPort,
		Handler:           agent.Routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		log.Printf("[HTTP] API de contrôle active sur http://%s", cfg.MetricsPort)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("[ERR HTTP] Serveur arrêté: %v", err)
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("[SHUTDOWN] Arrêt en cours...")
	cancel()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("[ERR HTTP] Arrêt propre échoué: %v", err)
	}

	if err := agent.ResetFirewall(); err != nil {
		log.Printf("[ERR KERNEL] Nettoyage iptables échoué: %v", err)
	}
}
