package pipeline

import "github.com/B3rt0oo/basic-intrusion-detection-system/internal/types"

// Detector is an interface for detection engines.
type Detector interface {
    Process(ev types.PacketEvent) []types.Alert
}

// Engine fans out events to detectors and aggregates their alerts.
type Engine struct {
    detectors []Detector
}

func NewEngine(detectors []Detector) *Engine {
    return &Engine{detectors: append([]Detector(nil), detectors...)}
}

func (e *Engine) Process(ev types.PacketEvent) []types.Alert {
    var out []types.Alert
    for _, d := range e.detectors {
        if alerts := d.Process(ev); len(alerts) > 0 {
            out = append(out, alerts...)
        }
    }
    return out
}

