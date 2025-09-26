package detect

import (
    "testing"
    "time"

    "github.com/B3rt0oo/basic-intrusion-detection-system/internal/types"
)

func TestDNSAnomaly_LongNameAndSubs(t *testing.T) {
    t.Parallel()
    det := NewDNSAnomalyDetector(DNSAnomalyConfig{Window: 10 * time.Second, UniqueSubsPerBaseThresh: 3, LongNameLength: 10, QueryRatePerSrcThreshold: 100})
    base := time.Now().UTC()
    src := "10.0.0.5"
    // Long name triggers
    a := det.Process(types.PacketEvent{TS: base, SrcIP: src, DNSQName: "averyverylongname.example.com."})
    if len(a) == 0 { t.Fatalf("expected long name alert") }

    // Unique subdomains
    names := []string{
        "a.a.example.com",
        "b.a.example.com",
        "c.a.example.com",
    }
    var alerts int
    for i, n := range names {
        al := det.Process(types.PacketEvent{TS: base.Add(time.Duration(i+1) * time.Second), SrcIP: src, DNSQName: n})
        alerts += len(al)
    }
    if alerts == 0 { t.Fatalf("expected at least one subdomain alert") }
}

