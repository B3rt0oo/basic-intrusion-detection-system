package detect

import (
    "time"

    "github.com/B3rt0oo/basic-intrusion-detection-system/internal/types"
)

// ConnRateConfig flags high connection attempt rates by a single source.
type ConnRateConfig struct {
    Threshold int           // number of events within window to trigger
    Window    time.Duration // sliding window size
}

type ConnRateDetector struct {
    cfg      ConnRateConfig
    attempts map[string][]time.Time // srcIP -> timestamps
}

func NewConnRateDetector(cfg ConnRateConfig) *ConnRateDetector {
    if cfg.Threshold <= 0 { cfg.Threshold = 100 }
    if cfg.Window <= 0 { cfg.Window = 10 * time.Second }
    return &ConnRateDetector{cfg: cfg, attempts: make(map[string][]time.Time)}
}

func (d *ConnRateDetector) Process(ev types.PacketEvent) []types.Alert {
    now := ev.TS
    windowStart := now.Add(-d.cfg.Window)
    hist := append(d.attempts[ev.SrcIP], now)
    // trim
    i := 0
    for ; i < len(hist); i++ {
        if !hist[i].Before(windowStart) { break }
    }
    if i > 0 { hist = hist[i:] }
    d.attempts[ev.SrcIP] = hist

    if len(hist) >= d.cfg.Threshold {
        return []types.Alert{{
            TS:         now,
            Type:       "conn_rate",
            Severity:   "medium",
            SrcIP:      ev.SrcIP,
            WindowSecs: int(d.cfg.Window / time.Second),
            Details:    "high connection attempt rate",
        }}
    }
    return nil
}

