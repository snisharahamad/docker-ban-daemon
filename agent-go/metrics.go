package main

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type PromMetrics struct {
	registry      *prometheus.Registry
	logsProcessed prometheus.Counter
	regexHits     prometheus.Counter
	decisions     *prometheus.CounterVec
	llmDuration   prometheus.Histogram
	activeBans    prometheus.Gauge
}

func newPromMetrics() *PromMetrics {
	reg := prometheus.NewRegistry()

	pm := &PromMetrics{
		registry: reg,
		logsProcessed: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "dockban_logs_processed_total",
			Help: "Nombre total de lignes de logs Docker analysées.",
		}),
		regexHits: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "dockban_regex_hits_total",
			Help: "Nombre de lignes suspectes détectées par le filtre L1 (regex).",
		}),
		decisions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "dockban_decisions_total",
			Help: "Décisions prises par moteur (cache, llm, heuristic) et verdict (threat, benign).",
		}, []string{"engine", "verdict"}),
		llmDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "dockban_llm_duration_seconds",
			Help:    "Latence des appels HTTP vers Ollama en secondes.",
			Buckets: []float64{0.05, 0.1, 0.25, 0.5, 0.75, 1.0, 1.5},
		}),
		activeBans: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "dockban_active_bans",
			Help: "Nombre d'adresses IP actuellement bloquées dans DOCKER-USER.",
		}),
	}

	reg.MustRegister(
		pm.logsProcessed,
		pm.regexHits,
		pm.decisions,
		pm.llmDuration,
		pm.activeBans,
	)

	return pm
}

func (p *PromMetrics) Handler() http.Handler {
	return promhttp.HandlerFor(p.registry, promhttp.HandlerOpts{})
}
