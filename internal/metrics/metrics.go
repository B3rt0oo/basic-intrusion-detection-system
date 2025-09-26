package metrics

import (
    "net/http"
    "net/http/pprof"
    "time"

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
    // ProcessLatency measures per-event processing time.
    ProcessLatency = promauto.NewHistogram(prometheus.HistogramOpts{
        Namespace: "ids", Subsystem: "pipeline", Name: "process_latency_seconds", Help: "Event processing latency",
        Buckets: prometheus.DefBuckets,
    })
)

// Serve starts an HTTP server exposing Prometheus metrics.
func Serve(addr string) error {
    mux := http.NewServeMux()
    mux.Handle("/metrics", promhttp.Handler())
    mux.HandleFunc("/debug/pprof/", pprof.Index)
    mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
    mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
    mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
    mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
    srv := &http.Server{Addr: addr, Handler: mux}
    return srv.ListenAndServe()
}

// ObserveDuration is a helper to record latency via defer.
func ObserveDuration(start time.Time) {
    dur := time.Since(start).Seconds()
    ProcessLatency.Observe(dur)
}
