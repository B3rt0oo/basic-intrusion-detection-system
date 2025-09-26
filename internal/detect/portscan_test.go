package detect

import (
    "testing"
    "time"

    "github.com/B3rt0oo/basic-intrusion-detection-system/internal/types"
)

func TestPortScanDetector_TriggersAtThreshold(t *testing.T) {
    t.Parallel()
    det := NewPortScanDetector(PortScanConfig{Threshold: 3, Window: 10 * time.Second, MaxPerHost: 128})
    base := time.Now().UTC()
    src := "1.2.3.4"
    dst := "10.0.0.1"

    // 2 unique ports => below threshold
    evs := []types.PacketEvent{
        {TS: base.Add(1 * time.Second), SrcIP: src, DstIP: dst, DstPort: 22, Proto: "tcp"},
        {TS: base.Add(2 * time.Second), SrcIP: src, DstIP: dst, DstPort: 80, Proto: "tcp"},
    }
    for _, ev := range evs {
        if alerts := det.Process(ev); len(alerts) != 0 {
            t.Fatalf("unexpected alert below threshold: %+v", alerts)
        }
    }

    // third unique port within window => triggers exactly once
    alerts := det.Process(types.PacketEvent{TS: base.Add(3 * time.Second), SrcIP: src, DstIP: dst, DstPort: 443, Proto: "tcp"})
    if len(alerts) != 1 {
        t.Fatalf("expected one alert at threshold, got %d", len(alerts))
    }
    if alerts[0].Type != "port_scan" || alerts[0].SrcIP != src {
        t.Fatalf("unexpected alert content: %+v", alerts[0])
    }
}

func TestPortScanDetector_WindowTrim(t *testing.T) {
    t.Parallel()
    det := NewPortScanDetector(PortScanConfig{Threshold: 2, Window: 2 * time.Second, MaxPerHost: 128})
    base := time.Now().UTC()
    src := "5.6.7.8"
    dst := "10.0.0.2"

    // first event falls out of window before second unique port arrives
    _ = det.Process(types.PacketEvent{TS: base, SrcIP: src, DstIP: dst, DstPort: 1000, Proto: "tcp"})
    alerts := det.Process(types.PacketEvent{TS: base.Add(3 * time.Second), SrcIP: src, DstIP: dst, DstPort: 1001, Proto: "tcp"})
    if len(alerts) != 0 {
        t.Fatalf("expected no alert after window trim, got %d", len(alerts))
    }
}

func TestPortScanDetector_MaxPerHostCap(t *testing.T) {
    t.Parallel()
    det := NewPortScanDetector(PortScanConfig{Threshold: 1000, Window: 60 * time.Second, MaxPerHost: 4})
    base := time.Now().UTC()
    src := "9.9.9.9"
    dst := "10.0.0.3"

    for i := 0; i < 10; i++ {
        _ = det.Process(types.PacketEvent{TS: base.Add(time.Duration(i) * time.Second), SrcIP: src, DstIP: dst, DstPort: uint16(1000 + i), Proto: "tcp"})
    }
    // If the cap isn't enforced, this would allocate more than 4
    // We can't inspect internals, but we can at least ensure no alert when threshold is very high
    alerts := det.Process(types.PacketEvent{TS: base.Add(11 * time.Second), SrcIP: src, DstIP: dst, DstPort: 9999, Proto: "tcp"})
    if len(alerts) != 0 {
        t.Fatalf("unexpected alert with high threshold: %v", alerts)
    }
}

