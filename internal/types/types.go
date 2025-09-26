package types

import "time"

// PacketEvent is a normalized representation of a single observed packet/session attempt.
// It is intentionally minimal to enable offline testing without a pcap dependency.
type PacketEvent struct {
    TS      time.Time `json:"ts"`
    SrcIP   string    `json:"src_ip"`
    DstIP   string    `json:"dst_ip"`
    DstPort uint16    `json:"dst_port"`
    Proto   string    `json:"proto"` // e.g., "tcp", "udp"
    // DNS (optional)
    DNSQName string `json:"dns_qname,omitempty"`
    DNSQType string `json:"dns_qtype,omitempty"`
    DNSResp  bool   `json:"dns_resp,omitempty"`
    DNSRcode string `json:"dns_rcode,omitempty"`
}

// Alert represents a detection output item.
type Alert struct {
    TS         time.Time `json:"ts"`
    Type       string    `json:"type"`
    Severity   string    `json:"severity"`
    SrcIP      string    `json:"src_ip"`
    DstIPs     []string  `json:"dst_ips,omitempty"`
    DstPorts   []uint16  `json:"dst_ports,omitempty"`
    WindowSecs int       `json:"window_secs"`
    Details    string    `json:"details,omitempty"`
}
