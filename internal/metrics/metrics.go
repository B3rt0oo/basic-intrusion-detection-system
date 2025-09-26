package metrics

import (
    "log"
    "net/http"

    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promauto"
    "github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
    // EventsTotal counts all processed events.
    EventsTotal = promauto.NewCounter(prometheus.CounterOpts{
        Namespace: "ids", Subsystem: "ingest", Name: "events_total", Help: "Total events processed",
    })
    // AlertsTotal counts alerts by type.
    AlertsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
        Namespace: "ids", Subsystem: "detect", Name: "alerts_total", Help: "Total alerts emitted by type",
    }, []string{"type"})
)

// Serve starts an HTTP server exposing Prometheus metrics.
func Serve(addr string) error {
    mux := http.NewServeMux()
    mux.Handle("/metrics", promhttp.Handler())
    srv := &http.Server{Addr: addr, Handler: mux}
    log.Printf("metrics listening on %s", addr)
    return srv.ListenAndServe()
}

