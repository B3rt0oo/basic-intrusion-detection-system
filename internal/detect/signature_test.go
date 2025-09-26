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

