package detect

import (
    "strings"

    "github.com/B3rt0oo/basic-intrusion-detection-system/internal/config"
    "github.com/B3rt0oo/basic-intrusion-detection-system/internal/types"
)

// SignatureDetector evaluates simple field-matching rules from config.
type SignatureDetector struct {
    rules []config.Rule
}

func NewSignatureDetector(rules []config.Rule) *SignatureDetector {
    return &SignatureDetector{rules: append([]config.Rule(nil), rules...)}
}

func (d *SignatureDetector) Process(ev types.PacketEvent) []types.Alert {
    var out []types.Alert
    for _, r := range d.rules {
        if !matchRule(r, ev) { continue }
        sev := r.Severity
        if sev == "" { sev = "low" }
        out = append(out, types.Alert{
            TS:       ev.TS,
            Type:     "signature",
            Severity: sev,
            SrcIP:    ev.SrcIP,
            DstIPs:   []string{ev.DstIP},
            DstPorts: []uint16{ev.DstPort},
            Details:  r.Name,
        })
    }
    return out
}

func matchRule(r config.Rule, ev types.PacketEvent) bool {
    if r.Proto != "" && !strings.EqualFold(r.Proto, ev.Proto) { return false }
    if r.SrcIP != "" && r.SrcIP != ev.SrcIP { return false }
    if r.DstIP != "" && r.DstIP != ev.DstIP { return false }
    if r.DstPort != 0 && int(ev.DstPort) != r.DstPort { return false }
    return true
}

