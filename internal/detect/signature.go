package detect

import (
    "net/netip"
    "regexp"
    "strconv"
    "strings"

    "github.com/B3rt0oo/basic-intrusion-detection-system/internal/config"
    "github.com/B3rt0oo/basic-intrusion-detection-system/internal/types"
)

// SignatureDetector evaluates field-matching rules from config, supporting CIDRs and port ranges.
type SignatureDetector struct {
    rules []compiledRule
}

type compiledRule struct {
    name     string
    severity string
    proto    string
    srcCIDR  *netip.Prefix
    dstCIDR  *netip.Prefix
    srcIP    string
    dstIP    string
    ports    portMatcher
    dnsSuf   string
    dnsRe    *regexp.Regexp
    dnsType  string
}

type portMatcher struct{
    // zero means match-any
    single int
    ranges [][2]int
    set    map[int]struct{}
}

func parsePorts(spec string, single int) portMatcher {
    var pm portMatcher
    pm.single = single
    if spec == "" { return pm }
    pm.set = make(map[int]struct{})
    for _, part := range strings.Split(spec, ",") {
        p := strings.TrimSpace(part)
        if p == "" { continue }
        if strings.Contains(p, "-") {
            toks := strings.SplitN(p, "-", 2)
            a, err1 := strconv.Atoi(strings.TrimSpace(toks[0]))
            b, err2 := strconv.Atoi(strings.TrimSpace(toks[1]))
            if err1 == nil && err2 == nil && a > 0 && b > 0 && a <= 65535 && b <= 65535 {
                if a > b { a, b = b, a }
                pm.ranges = append(pm.ranges, [2]int{a, b})
            }
            continue
        }
        if v, err := strconv.Atoi(p); err == nil && v > 0 && v <= 65535 {
            pm.set[v] = struct{}{}
        }
    }
    return pm
}

func (pm portMatcher) Match(port uint16) bool {
    p := int(port)
    if pm.single != 0 && p == pm.single { return true }
    if pm.set != nil {
        if _, ok := pm.set[p]; ok { return true }
    }
    for _, rg := range pm.ranges {
        if p >= rg[0] && p <= rg[1] { return true }
    }
    // if nothing specified, match any
    return pm.single == 0 && pm.set == nil && len(pm.ranges) == 0
}

func NewSignatureDetector(rules []config.Rule) *SignatureDetector {
    out := make([]compiledRule, 0, len(rules))
    for _, r := range rules {
        cr := compiledRule{name: r.Name, severity: r.Severity, proto: strings.ToLower(r.Proto), srcIP: r.SrcIP, dstIP: r.DstIP}
        if cr.severity == "" { cr.severity = "low" }
        if r.SrcCIDR != "" {
            if pfx, err := netip.ParsePrefix(r.SrcCIDR); err == nil { cr.srcCIDR = &pfx }
        }
        if r.DstCIDR != "" {
            if pfx, err := netip.ParsePrefix(r.DstCIDR); err == nil { cr.dstCIDR = &pfx }
        }
        cr.ports = parsePorts(r.DstPorts, r.DstPort)
        cr.dnsSuf = strings.ToLower(strings.TrimSuffix(r.DNSQnameSuffix, "."))
        cr.dnsType = strings.ToUpper(r.DNSQtype)
        if r.DNSQnameRegex != "" {
            if re, err := regexp.Compile(r.DNSQnameRegex); err == nil { cr.dnsRe = re }
        }
        out = append(out, cr)
    }
    return &SignatureDetector{rules: out}
}

func (d *SignatureDetector) Process(ev types.PacketEvent) []types.Alert {
    var out []types.Alert
    for _, r := range d.rules {
        if !sigMatch(r, ev) { continue }
        out = append(out, types.Alert{
            TS:       ev.TS,
            Type:     "signature",
            Severity: r.severity,
            SrcIP:    ev.SrcIP,
            DstIPs:   []string{ev.DstIP},
            DstPorts: []uint16{ev.DstPort},
            Details:  r.name,
        })
    }
    return out
}

func sigMatch(r compiledRule, ev types.PacketEvent) bool {
    if r.proto != "" && r.proto != strings.ToLower(ev.Proto) { return false }
    if r.srcCIDR != nil {
        if addr, err := netip.ParseAddr(ev.SrcIP); err == nil {
            if !r.srcCIDR.Contains(addr) { return false }
        } else { return false }
    }
    if r.dstCIDR != nil {
        if addr, err := netip.ParseAddr(ev.DstIP); err == nil {
            if !r.dstCIDR.Contains(addr) { return false }
        } else { return false }
    }
    if r.srcIP != "" && r.srcIP != ev.SrcIP { return false }
    if r.dstIP != "" && r.dstIP != ev.DstIP { return false }
    if !r.ports.Match(ev.DstPort) { return false }
    // DNS matchers (optional)
    if r.dnsSuf != "" {
        qn := strings.TrimSuffix(strings.ToLower(ev.DNSQName), ".")
        if !strings.HasSuffix(qn, r.dnsSuf) { return false }
    }
    if r.dnsRe != nil {
        if !r.dnsRe.MatchString(ev.DNSQName) { return false }
    }
    if r.dnsType != "" {
        if strings.ToUpper(ev.DNSQType) != r.dnsType { return false }
    }
    return true
}
