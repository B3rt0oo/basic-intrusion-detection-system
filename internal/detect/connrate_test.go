package detect

import (
    "testing"
    "time"

    "github.com/B3rt0oo/basic-intrusion-detection-system/internal/types"
)

func TestConnRateDetector_Triggers(t *testing.T) {
    t.Parallel()
    det := NewConnRateDetector(ConnRateConfig{Threshold: 3, Window: 2 * time.Second})
    base := time.Now().UTC()
    src := "2.2.2.2"

    // first two within window, no alert yet
    _ = det.Process(types.PacketEvent{TS: base, SrcIP: src})
    _ = det.Process(types.PacketEvent{TS: base.Add(500 * time.Millisecond), SrcIP: src})
    if a := det.Process(types.PacketEvent{TS: base.Add(1 * time.Second), SrcIP: src}); len(a) != 1 {
        t.Fatalf("expected one alert, got %d", len(a))
    }
}

func TestConnRateDetector_WindowDropsOld(t *testing.T) {
    t.Parallel()
    det := NewConnRateDetector(ConnRateConfig{Threshold: 2, Window: 1 * time.Second})
    base := time.Now().UTC()
    src := "3.3.3.3"

    _ = det.Process(types.PacketEvent{TS: base, SrcIP: src})
    if a := det.Process(types.PacketEvent{TS: base.Add(1500 * time.Millisecond), SrcIP: src}); len(a) != 0 {
        t.Fatalf("expected no alert; old event should be dropped")
    }
}

