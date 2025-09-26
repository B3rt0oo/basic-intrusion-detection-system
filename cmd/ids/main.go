package main

import (
    "flag"
    "fmt"
    "os"
    "time"

    "github.com/B3rt0oo/basic-intrusion-detection-system/internal/alert"
    "github.com/B3rt0oo/basic-intrusion-detection-system/internal/capture"
    "github.com/B3rt0oo/basic-intrusion-detection-system/internal/config"
    "github.com/B3rt0oo/basic-intrusion-detection-system/internal/detect"
    "github.com/B3rt0oo/basic-intrusion-detection-system/internal/metrics"
    "github.com/B3rt0oo/basic-intrusion-detection-system/internal/pipeline"
    "github.com/B3rt0oo/basic-intrusion-detection-system/internal/types"
)

// CLI: reads JSONL events from stdin (for now) and outputs alerts to stdout and/or file.
func main() {
    var cfgPath string
    flag.StringVar(&cfgPath, "config", "", "path to JSON config file")
    metricsAddr := flag.String("metrics-listen", "", "if set, serve Prometheus metrics on this address (e.g., :9090)")
    flag.Parse()

    cfg, err := config.Load(cfgPath)
    if err != nil {
        fmt.Fprintf(os.Stderr, "failed to load config: %v\n", err)
        os.Exit(2)
    }

    // Build detectors
    var dets []pipeline.Detector
    if cfg.PortScan.Enabled {
        dets = append(dets, detect.NewPortScanDetector(detect.PortScanConfig{
            Threshold:  cfg.PortScan.Threshold,
            Window:     cfg.PortScan.Window,
            MaxPerHost: cfg.PortScan.MaxPerHost,
        }))
    }
    if cfg.ConnRate.Enabled {
        dets = append(dets, detect.NewConnRateDetector(detect.ConnRateConfig{
            Threshold: cfg.ConnRate.Threshold,
            Window:    cfg.ConnRate.Window,
        }))
    }
    if len(cfg.Rules) > 0 {
        dets = append(dets, detect.NewSignatureDetector(cfg.Rules))
    }
    eng := pipeline.NewEngine(dets)

    if *metricsAddr != "" {
        go func() {
            if err := metrics.Serve(*metricsAddr); err != nil {
                fmt.Fprintf(os.Stderr, "metrics server failed: %v\n", err)
            }
        }()
    }

    // Build sinks
    var sinks []alert.Sink
    if cfg.Alerts.Stdout {
        sinks = append(sinks, alert.StdoutSink{})
    }
    if cfg.Alerts.File != "" {
        s, err := alert.NewFileSink(cfg.Alerts.File)
        if err != nil {
            fmt.Fprintf(os.Stderr, "failed to open alert file: %v\n", err)
            os.Exit(2)
        }
        defer s.Close()
        sinks = append(sinks, s)
    }
    if cfg.Alerts.Syslog {
        s, err := alert.NewSyslogSink("ids")
        if err != nil {
            fmt.Fprintf(os.Stderr, "syslog init failed: %v\n", err)
            os.Exit(2)
        }
        defer s.Close()
        sinks = append(sinks, s)
    }
    if len(sinks) == 0 {
        fmt.Fprintln(os.Stderr, "no alert sinks configured; enable stdout or file")
        os.Exit(2)
    }

    // Source selection
    var src interface{ Next() (types.PacketEvent, bool) }
    switch cfg.Input.Type {
    case "jsonl-stdin":
        src = capture.NewJSONLSource(os.Stdin)
    case "pcap-live":
        live, err := capture.NewLivePCAPSource(cfg.Input.Device, cfg.Input.BPF)
        if err != nil {
            fmt.Fprintf(os.Stderr, "pcap init failed: %v\n", err)
            os.Exit(2)
        }
        src = live
    default:
        fmt.Fprintf(os.Stderr, "unsupported input type: %s\n", cfg.Input.Type)
        os.Exit(2)
    }

    for {
        ev, ok := src.Next()
        if !ok {
            break
        }
        if ev.TS.IsZero() {
            ev.TS = time.Now().UTC()
        }
        metrics.EventsTotal.Inc()
        alerts := eng.Process(ev)
        for _, a := range alerts {
            for _, s := range sinks {
                _ = s.Emit(a)
            }
            metrics.AlertsTotal.WithLabelValues(a.Type).Inc()
        }
    }
}
