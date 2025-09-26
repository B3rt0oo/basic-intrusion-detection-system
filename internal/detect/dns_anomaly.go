package detect

import (
    "strings"
    "time"

    "golang.org/x/net/publicsuffix"

    "github.com/B3rt0oo/basic-intrusion-detection-system/internal/types"
)

type DNSAnomalyConfig struct {
    Enabled                  bool
    Window                   time.Duration
    UniqueSubsPerBaseThresh  int    // unique subdomains per base within window
    LongNameLength           int    // single fqdn length threshold
    QueryRatePerSrcThreshold int    // total queries per src within window
}

type DNSAnomalyDetector struct {
    cfg DNSAnomalyConfig
    // state keyed by srcIP
    queries map[string][]dnsObs
}

type dnsObs struct {
    ts   time.Time
    base string
    sub  string
    fqdn string
}

func NewDNSAnomalyDetector(cfg DNSAnomalyConfig) *DNSAnomalyDetector {
    if cfg.Window <= 0 { cfg.Window = 60 * time.Second }
    if cfg.UniqueSubsPerBaseThresh <= 0 { cfg.UniqueSubsPerBaseThresh = 50 }
    if cfg.LongNameLength <= 0 { cfg.LongNameLength = 60 }
    if cfg.QueryRatePerSrcThreshold <= 0 { cfg.QueryRatePerSrcThreshold = 200 }
    return &DNSAnomalyDetector{cfg: cfg, queries: make(map[string][]dnsObs)}
}

func (d *DNSAnomalyDetector) Process(ev types.PacketEvent) []types.Alert {
    if ev.DNSQName == "" { return nil }
    now := ev.TS
    windowStart := now.Add(-d.cfg.Window)

    base, sub := splitBaseSub(ev.DNSQName)
    obs := dnsObs{ts: now, base: base, sub: sub, fqdn: ev.DNSQName}
    hist := append(d.queries[ev.SrcIP], obs)
    // trim by time
    i := 0
    for ; i < len(hist); i++ {
        if !hist[i].ts.Before(windowStart) { break }
    }
    if i > 0 { hist = hist[i:] }
    d.queries[ev.SrcIP] = hist

    var alerts []types.Alert

    // Long single name
    if len(ev.DNSQName) >= d.cfg.LongNameLength {
        alerts = append(alerts, types.Alert{
            TS:       now,
            Type:     "dns_long_name",
            Severity: "low",
            SrcIP:    ev.SrcIP,
            Details:  ev.DNSQName,
        })
    }

    // Unique subdomains per base
    subs := make(map[string]struct{})
    count := 0
    for _, h := range hist {
        if h.base == base {
            subs[h.sub] = struct{}{}
        }
        // count all queries for rate
        count++
    }
    if len(subs) >= d.cfg.UniqueSubsPerBaseThresh && base != "" {
        alerts = append(alerts, types.Alert{
            TS:         now,
            Type:       "dns_tunnel_suspect",
            Severity:   "medium",
            SrcIP:      ev.SrcIP,
            WindowSecs: int(d.cfg.Window / time.Second),
            Details:    "many unique subdomains for base: " + base,
        })
    }

    // High query rate per src
    if count >= d.cfg.QueryRatePerSrcThreshold {
        alerts = append(alerts, types.Alert{
            TS:         now,
            Type:       "dns_rate",
            Severity:   "low",
            SrcIP:      ev.SrcIP,
            WindowSecs: int(d.cfg.Window / time.Second),
            Details:    "high DNS query rate",
        })
    }

    return alerts
}

func splitBaseSub(qname string) (base string, sub string) {
    s := strings.TrimSuffix(strings.ToLower(qname), ".")
    if s == "" { return "", "" }
    if e1, err := publicsuffix.EffectiveTLDPlusOne(s); err == nil {
        if len(s) <= len(e1) { return e1, "" }
        return e1, strings.TrimSuffix(strings.TrimSuffix(s, e1), ".")
    }
    // fallback: last two labels as base
    parts := strings.Split(s, ".")
    if len(parts) < 2 { return s, "" }
    base = parts[len(parts)-2] + "." + parts[len(parts)-1]
    sub = strings.TrimSuffix(s, "."+base)
    return
}

