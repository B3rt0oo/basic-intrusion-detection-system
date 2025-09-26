package detect

import (
    "testing"
    "time"

    "github.com/B3rt0oo/basic-intrusion-detection-system/internal/config"
    "github.com/B3rt0oo/basic-intrusion-detection-system/internal/types"
)

func TestSignatureDetector_MatchAndNoMatch(t *testing.T) {
    t.Parallel()
    det := NewSignatureDetector([]config.Rule{{
        Name: "SSH Access", Severity: "low", Proto: "tcp", DstPort: 22,
    }})
    ts := time.Now().UTC()
    // Match
    al := det.Process(types.PacketEvent{TS: ts, SrcIP: "1.1.1.1", DstIP: "2.2.2.2", DstPort: 22, Proto: "tcp"})
    if len(al) != 1 { t.Fatalf("expected 1 alert, got %d", len(al)) }
    // No match
    al2 := det.Process(types.PacketEvent{TS: ts, SrcIP: "1.1.1.1", DstIP: "2.2.2.2", DstPort: 23, Proto: "tcp"})
    if len(al2) != 0 { t.Fatalf("expected 0 alerts, got %d", len(al2)) }
}

func TestSignatureDetector_CIDRAndPortRanges(t *testing.T) {
    t.Parallel()
    rules := []config.Rule{{
        Name: "RFC1918 src to SSH", Severity: "high", Proto: "tcp", SrcCIDR: "10.0.0.0/8", DstPorts: "20-25,80,443",
    }}
    det := NewSignatureDetector(rules)
    ts := time.Now().UTC()

    // src in cidr & port in range -> match
    a := det.Process(types.PacketEvent{TS: ts, SrcIP: "10.1.2.3", DstIP: "203.0.113.1", DstPort: 22, Proto: "tcp"})
    if len(a) != 1 { t.Fatalf("expected match for CIDR and range, got %d", len(a)) }

    // src outside cidr -> no match
    b := det.Process(types.PacketEvent{TS: ts, SrcIP: "192.0.2.10", DstIP: "203.0.113.1", DstPort: 22, Proto: "tcp"})
    if len(b) != 0 { t.Fatalf("expected no match for outside CIDR, got %d", len(b)) }
}
