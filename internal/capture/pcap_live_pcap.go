//go:build pcap

package capture

import (
    "time"

    "github.com/B3rt0oo/basic-intrusion-detection-system/internal/types"
    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket/pcap"
)

// LivePCAPSource emits PacketEvents from a live interface using libpcap.
type LivePCAPSource struct {
    src    gopacket.PacketSource
    packets <-chan gopacket.Packet
}

func NewLivePCAPSource(device, bpf string) (*LivePCAPSource, error) {
    handle, err := pcap.OpenLive(device, 65535, true, pcap.BlockForever)
    if err != nil { return nil, err }
    if bpf != "" {
        _ = handle.SetBPFFilter(bpf)
    }
    src := gopacket.NewPacketSource(handle, handle.LinkType())
    return &LivePCAPSource{src: *src, packets: src.Packets()}, nil
}

func (s *LivePCAPSource) Next() (types.PacketEvent, bool) {
    pkt, ok := <-s.packets
    if !ok { return types.PacketEvent{}, false }
    var ev types.PacketEvent
    ev.TS = pkt.Metadata().Timestamp

    if ip := pkt.Layer(layers.LayerTypeIPv4); ip != nil {
        ipv4 := ip.(*layers.IPv4)
        ev.SrcIP = ipv4.SrcIP.String()
        ev.DstIP = ipv4.DstIP.String()
        ev.Proto = "ip"
    }
    if ip6 := pkt.Layer(layers.LayerTypeIPv6); ip6 != nil {
        ipv6 := ip6.(*layers.IPv6)
        ev.SrcIP = ipv6.SrcIP.String()
        ev.DstIP = ipv6.DstIP.String()
        ev.Proto = "ip6"
    }
    if dnsL := pkt.Layer(layers.LayerTypeDNS); dnsL != nil {
        dns := dnsL.(*layers.DNS)
        ev.Proto = "dns"
        if dns.QR == false && len(dns.Questions) > 0 { // query
            ev.DNSQName = string(dns.Questions[0].Name)
            ev.DNSQType = dns.Questions[0].Type.String()
            ev.DNSResp = false
            ev.DNSRcode = ""
        } else if dns.QR == true { // response
            ev.DNSResp = true
            ev.DNSRcode = dns.ResponseCode.String()
            if len(dns.Questions) > 0 {
                ev.DNSQName = string(dns.Questions[0].Name)
                ev.DNSQType = dns.Questions[0].Type.String()
            }
        }
    }
    if tcpL := pkt.Layer(layers.LayerTypeTCP); tcpL != nil {
        tcp := tcpL.(*layers.TCP)
        ev.DstPort = uint16(tcp.DstPort)
        ev.Proto = "tcp"
    } else if udpL := pkt.Layer(layers.LayerTypeUDP); udpL != nil {
        udp := udpL.(*layers.UDP)
        ev.DstPort = uint16(udp.DstPort)
        if ev.Proto == "" { ev.Proto = "udp" }
    }
    if ev.TS.IsZero() { ev.TS = time.Now().UTC() }
    return ev, true
}
