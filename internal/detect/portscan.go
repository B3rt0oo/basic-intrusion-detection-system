package detect

import (
    "sort"
    "time"

    "github.com/B3rt0oo/basic-intrusion-detection-system/internal/types"
)

// PortScanConfig controls the detector sensitivity and memory bounds.
type PortScanConfig struct {
    Threshold  int           // unique destination ports in window to trigger alert
    Window     time.Duration // sliding window size
    MaxPerHost int           // cap per-host attempt history to avoid unbounded memory
}

// PortScanDetector flags sources hitting many unique destination ports quickly.
type PortScanDetector struct {
    cfg PortScanConfig
    // attempts[src] = ring/list of (ts, dstPort, dstIP)
    attempts map[string][]attempt
}

type attempt struct {
    ts      time.Time
    dstPort uint16
    dstIP   string
}

func NewPortScanDetector(cfg PortScanConfig) *PortScanDetector {
    if cfg.Threshold <= 0 {
        cfg.Threshold = 10
    }
    if cfg.Window <= 0 {
        cfg.Window = 60 * time.Second
    }
    if cfg.MaxPerHost <= 0 {
        cfg.MaxPerHost = 4096
    }
    return &PortScanDetector{
        cfg:      cfg,
        attempts: make(map[string][]attempt),
    }
}

// Process consumes an event and returns zero or more alerts.
func (d *PortScanDetector) Process(ev types.PacketEvent) []types.Alert {
    now := ev.TS
    a := attempt{ts: now, dstPort: ev.DstPort, dstIP: ev.DstIP}
    windowStart := now.Add(-d.cfg.Window)

    hist := d.attempts[ev.SrcIP]
    // append and trim by time
    hist = append(hist, a)
    // drop old
    i := 0
    for ; i < len(hist); i++ {
        if hist[i].ts.After(windowStart) || hist[i].ts.Equal(windowStart) {
            break
        }
    }
    if i > 0 {
        hist = hist[i:]
    }
    // enforce cap
    if over := len(hist) - d.cfg.MaxPerHost; over > 0 {
        hist = hist[over:]
    }
    d.attempts[ev.SrcIP] = hist

    // unique ports and destinations in window
    portsSet := make(map[uint16]struct{})
    dstSet := make(map[string]struct{})
    for _, h := range hist {
        portsSet[h.dstPort] = struct{}{}
        dstSet[h.dstIP] = struct{}{}
    }
    if len(portsSet) >= d.cfg.Threshold {
        // build sorted lists for stable output
        ports := make([]uint16, 0, len(portsSet))
        for p := range portsSet {
            ports = append(ports, p)
        }
        sort.Slice(ports, func(i, j int) bool { return ports[i] < ports[j] })
        dsts := make([]string, 0, len(dstSet))
        for ip := range dstSet {
            dsts = append(dsts, ip)
        }
        sort.Strings(dsts)
        return []types.Alert{{
            TS:         now,
            Type:       "port_scan",
            Severity:   "medium",
            SrcIP:      ev.SrcIP,
            DstIPs:     dsts,
            DstPorts:   ports,
            WindowSecs: int(d.cfg.Window / time.Second),
            Details:    "multiple unique destination ports in window",
        }}
    }
    return nil
}

