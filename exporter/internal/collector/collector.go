// Package collector implements a Prometheus collector that reads vpp-ndpi
// stats from the VPP stats segment socket and exposes them as Prometheus
// metrics.
//
// Stats paths consumed:
//
//	/ndpi/flows_created        → vpp_ndpi_flows_created_total
//	/ndpi/flows_classified     → vpp_ndpi_flows_classified_total
//	/ndpi/flows_gave_up        → vpp_ndpi_flows_gave_up_total
//	/ndpi/flows_active         → vpp_ndpi_flows_active
//	/ndpi/packets_scanned      → vpp_ndpi_packets_scanned_total
//	/ndpi/packets_cached       → vpp_ndpi_packets_cached_total
//	/ndpi/ndpi_calls           → vpp_ndpi_ndpi_calls_total
//	/ndpi/app/<Name>/bytes     → vpp_ndpi_app_bytes_total{app="<Name>"}
//	/ndpi/app/<Name>/packets   → vpp_ndpi_app_packets_total{app="<Name>"}
//	/ndpi/app/<Name>/flows     → vpp_ndpi_app_flows_total{app="<Name>"}
package collector

import (
	"log"
	"regexp"
	"strings"

	"go.fd.io/govpp/adapter"
	"go.fd.io/govpp/adapter/statsclient"
	"github.com/prometheus/client_golang/prometheus"
)

var appPathRe = regexp.MustCompile(`^/ndpi/app/([^/]+)/(bytes|packets|flows)$`)

// metricDesc groups a prometheus.Desc with its Prometheus value type.
type metricDesc struct {
	desc      *prometheus.Desc
	valueType prometheus.ValueType
}

// VppCollector scrapes the VPP stats socket on every Collect() call.
type VppCollector struct {
	socket string

	// Pre-built Descs for the fixed global metrics, keyed by stats path.
	descs map[string]metricDesc

	// Per-app metric Descs (shared across all apps via label).
	appBytesDesc   *prometheus.Desc
	appPacketsDesc *prometheus.Desc
	appFlowsDesc   *prometheus.Desc
}

// New creates a VppCollector that connects to the given VPP stats socket path.
func New(statsSocket string) *VppCollector {
	ns := "vpp_ndpi"

	return &VppCollector{
		socket: statsSocket,
		descs: map[string]metricDesc{
			"/ndpi/flows_created": {
				desc:      prometheus.NewDesc(ns+"_flows_created_total", "Cumulative flows created", nil, nil),
				valueType: prometheus.CounterValue,
			},
			"/ndpi/flows_classified": {
				desc:      prometheus.NewDesc(ns+"_flows_classified_total", "Flows with classification verdict", nil, nil),
				valueType: prometheus.CounterValue,
			},
			"/ndpi/flows_gave_up": {
				desc:      prometheus.NewDesc(ns+"_flows_gave_up_total", "Flows timed out before verdict", nil, nil),
				valueType: prometheus.CounterValue,
			},
			"/ndpi/flows_active": {
				desc:      prometheus.NewDesc(ns+"_flows_active", "Currently active flows", nil, nil),
				valueType: prometheus.GaugeValue,
			},
			"/ndpi/packets_scanned": {
				desc:      prometheus.NewDesc(ns+"_packets_scanned_total", "Packets submitted to nDPI engine", nil, nil),
				valueType: prometheus.CounterValue,
			},
			"/ndpi/packets_cached": {
				desc:      prometheus.NewDesc(ns+"_packets_cached_total", "Packets resolved from flow cache (no re-scan)", nil, nil),
				valueType: prometheus.CounterValue,
			},
			"/ndpi/ndpi_calls": {
				desc:      prometheus.NewDesc(ns+"_ndpi_calls_total", "ndpi_detection_process_packet() invocations", nil, nil),
				valueType: prometheus.CounterValue,
			},
		},
		appBytesDesc:   prometheus.NewDesc(ns+"_app_bytes_total", "Bytes attributed to application", []string{"app"}, nil),
		appPacketsDesc: prometheus.NewDesc(ns+"_app_packets_total", "Packets attributed to application", []string{"app"}, nil),
		appFlowsDesc:   prometheus.NewDesc(ns+"_app_flows_total", "Flows attributed to application", []string{"app"}, nil),
	}
}

// Describe implements prometheus.Collector.
func (c *VppCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range c.descs {
		ch <- d.desc
	}
	ch <- c.appBytesDesc
	ch <- c.appPacketsDesc
	ch <- c.appFlowsDesc
}

// Collect implements prometheus.Collector.  Opens a fresh connection to the
// VPP stats socket, dumps all /ndpi/ entries, and emits Prometheus metrics.
func (c *VppCollector) Collect(ch chan<- prometheus.Metric) {
	sc := statsclient.NewStatsClient(c.socket)
	if err := sc.Connect(); err != nil {
		log.Printf("vpp-exporter: stats connect failed: %v", err)
		return
	}
	defer sc.Disconnect()

	entries, err := sc.DumpStats("/ndpi/")
	if err != nil {
		log.Printf("vpp-exporter: DumpStats failed: %v", err)
		return
	}

	for _, entry := range entries {
		scalar, ok := entry.Data.(adapter.ScalarStat)
		if !ok {
			continue
		}
		value := float64(scalar)
		name := string(entry.Name)

		// Global fixed metrics.
		if d, found := c.descs[name]; found {
			ch <- prometheus.MustNewConstMetric(d.desc, d.valueType, value)
			continue
		}

		// Per-app metrics: /ndpi/app/<Name>/(bytes|packets|flows)
		m := appPathRe.FindStringSubmatch(name)
		if m == nil {
			continue
		}
		appName := sanitizeLabel(m[1])
		metric := m[2]
		switch metric {
		case "bytes":
			ch <- prometheus.MustNewConstMetric(c.appBytesDesc, prometheus.CounterValue, value, appName)
		case "packets":
			ch <- prometheus.MustNewConstMetric(c.appPacketsDesc, prometheus.CounterValue, value, appName)
		case "flows":
			ch <- prometheus.MustNewConstMetric(c.appFlowsDesc, prometheus.CounterValue, value, appName)
		}
	}
}

// sanitizeLabel converts the underscore-escaped protocol name back to a
// human-readable form.  VPP stats paths replace spaces/dots with '_' so we
// restore single underscores to spaces (heuristic, good enough for labels).
func sanitizeLabel(s string) string {
	// Double underscores represent a literal underscore; single → space.
	s = strings.ReplaceAll(s, "__", "\x00")
	s = strings.ReplaceAll(s, "_", " ")
	s = strings.ReplaceAll(s, "\x00", "_")
	return s
}
