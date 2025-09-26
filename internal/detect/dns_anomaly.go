package detect

import (
    "math"
    "strings"
    "time"

    "golang.org/x/net/publicsuffix"

    "github.com/B3rt0oo/basic-intrusion-detection-system/internal/types"
)

type DNSAnomalyConfig struct {
    Enabled                  bool
    Window                   time.Duration
    UniqueSubsPerBaseThresh  int     // unique subdomains per base within window
    LongNameLength           int     // single fqdn length threshold
    QueryRatePerSrcThreshold int     // total queries per src within window
    EntropyThreshold         float64
    NxDomainRatioThreshold   float64 // 0..1, require MinResponses to evaluate
    MinResponses             int
}

type DNSAnomalyDetector struct {
    cfg DNSAnomalyConfig
    // state keyed by srcIP
    queries map[string][]dnsObs
}

type dnsObs struct {
    ts    time.Time
    base  string
    sub   string
    fqdn  string
    rcode string
}

func NewDNSAnomalyDetector(cfg DNSAnomalyConfig) *DNSAnomalyDetector {
    if cfg.Window <= 0 { cfg.Window = 60 * time.Second }
    if cfg.UniqueSubsPerBaseThresh <= 0 { cfg.UniqueSubsPerBaseThresh = 50 }
    if cfg.LongNameLength <= 0 { cfg.LongNameLength = 60 }
    if cfg.QueryRatePerSrcThreshold <= 0 { cfg.QueryRatePerSrcThreshold = 200 }
    if cfg.EntropyThreshold <= 0 { cfg.EntropyThreshold = 3.5 }
    if cfg.NxDomainRatioThreshold <= 0 { cfg.NxDomainRatioThreshold = 0.5 }
    if cfg.MinResponses <= 0 { cfg.MinResponses = 20 }
    return &DNSAnomalyDetector{cfg: cfg, queries: make(map[string][]dnsObs)}
}

func (d *DNSAnomalyDetector) Process(ev types.PacketEvent) []types.Alert {
    if ev.DNSQName == "" { return nil }
    now := ev.TS
    windowStart := now.Add(-d.cfg.Window)

    base, sub := splitBaseSub(ev.DNSQName)
    rc := ""
    if ev.DNSResp { rc = ev.DNSRcode }
    obs := dnsObs{ts: now, base: base, sub: sub, fqdn: ev.DNSQName, rcode: rc}
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
    resp := 0
    nxd := 0
    for _, h := range hist {
        if h.base == base {
            subs[h.sub] = struct{}{}
        }
        // count all queries for rate
        count++
        if h.rcode != "" { resp++ }
        if h.rcode == "NXDOMAIN" { nxd++ }
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

    // NXDOMAIN ratio alert
    if resp >= d.cfg.MinResponses && resp > 0 {
        ratio := float64(nxd) / float64(resp)
        if ratio >= d.cfg.NxDomainRatioThreshold {
            alerts = append(alerts, types.Alert{
                TS:         now,
                Type:       "dns_nxdomain_ratio",
                Severity:   "low",
                SrcIP:      ev.SrcIP,
                WindowSecs: int(d.cfg.Window / time.Second),
                Details:    "high NXDOMAIN ratio",
            })
        }
    }

    // High-entropy subdomain suspicious
    if sub != "" {
        if ent := shannonEntropy(sub); ent >= d.cfg.EntropyThreshold && len(ev.DNSQName) >= d.cfg.LongNameLength {
            alerts = append(alerts, types.Alert{
                TS:       now,
                Type:     "dns_entropy",
                Severity: "low",
                SrcIP:    ev.SrcIP,
                Details:  ev.DNSQName,
            })
        }
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

func shannonEntropy(s string) float64 {
    if s == "" { return 0 }
    var counts [256]int
    for i := 0; i < len(s); i++ {
        counts[s[i]]++
    }
    var ent float64
    n := float64(len(s))
    for i := 0; i < len(counts); i++ {
        if counts[i] == 0 { continue }
        p := float64(counts[i]) / n
        ent -= p * math.Log2(p)
    }
    return ent
}
