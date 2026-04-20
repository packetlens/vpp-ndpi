// vpp-exporter: Prometheus metrics exporter for FlowLens / vpp-ndpi.
//
// Reads application-visibility statistics from the VPP stats segment and
// exposes them at /metrics for Prometheus scraping.
//
// Usage:
//
//	vpp-exporter [--stats-socket PATH] [--listen ADDR]
//
// Defaults: socket=/run/vpp/stats.sock, listen=:9197
package main

import (
	"flag"
	"log"
	"net/http"

	"github.com/packetlens/vpp-ndpi/exporter/internal/collector"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
	statsSocket := flag.String("stats-socket", "/run/vpp/stats.sock",
		"Path to VPP stats segment socket")
	listenAddr := flag.String("listen", ":9197",
		"Address to listen on for Prometheus scrapes (host:port)")
	flag.Parse()

	reg := prometheus.NewRegistry()
	reg.MustRegister(collector.New(*statsSocket))

	http.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{
		EnableOpenMetrics: false,
	}))
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html><head><title>vpp-exporter</title></head><body>
<h1>FlowLens VPP Exporter</h1>
<p><a href="/metrics">Metrics</a></p>
</body></html>`))
	})

	log.Printf("vpp-exporter listening on %s (stats socket: %s)",
		*listenAddr, *statsSocket)
	if err := http.ListenAndServe(*listenAddr, nil); err != nil {
		log.Fatalf("listen: %v", err)
	}
}
