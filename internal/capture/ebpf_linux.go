//go:build ebpf && linux

package capture

import (
    "encoding/binary"
    "errors"
    "fmt"
    "net"
    "time"

    "github.com/B3rt0oo/basic-intrusion-detection-system/internal/types"
    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/ringbuf"
)

// EBPFLiveSource consumes events from a ringbuffer map named "events".
type EBPFLiveSource struct {
    reader *ringbuf.Reader
    ch     chan types.PacketEvent
}

// NewEBPFSource loads the object and opens the ringbuf, then starts a reader goroutine.
// It does not attach programs; attach externally or compile programs into the object.
func NewEBPFSource(objPath string) (*EBPFLiveSource, error) {
    if objPath == "" {
        return nil, errors.New("ebpf object path required; set input.program")
    }
    spec, err := ebpf.LoadCollectionSpec(objPath)
    if err != nil {
        return nil, fmt.Errorf("load ebpf spec: %w", err)
    }
    coll, err := ebpf.NewCollection(spec)
    if err != nil {
        return nil, fmt.Errorf("new ebpf collection: %w", err)
    }
    m, ok := coll.Maps["events"]
    if !ok {
        return nil, errors.New("ringbuf map 'events' not found in object")
    }
    r, err := ringbuf.NewReader(m)
    if err != nil {
        return nil, fmt.Errorf("ringbuf open: %w", err)
    }
    src := &EBPFLiveSource{reader: r, ch: make(chan types.PacketEvent, 1024)}
    go src.loop()
    return src, nil
}

func (s *EBPFLiveSource) loop() {
    defer s.reader.Close()
    var rec ringbuf.Record
    for {
        if err := s.reader.ReadInto(&rec); err != nil {
            close(s.ch)
            return
        }
        ev := parseEvent(rec.RawSample)
        s.ch <- ev
    }
}

func parseEvent(b []byte) types.PacketEvent {
    // Match struct event_v4 from bpf/ids_kern.c
    if len(b) < 8+4+4+2+1 {
        return types.PacketEvent{}
    }
    ts := int64(binary.LittleEndian.Uint64(b[0:8]))
    src := net.IPv4(b[8], b[9], b[10], b[11]).String()
    dst := net.IPv4(b[12], b[13], b[14], b[15]).String()
    port := binary.LittleEndian.Uint16(b[16:18])
    proto := b[18]
    p := ""
    switch proto {
    case 6:
        p = "tcp"
    case 17:
        p = "udp"
    default:
        p = "ip"
    }
    return types.PacketEvent{TS: time.Unix(0, ts), SrcIP: src, DstIP: dst, DstPort: port, Proto: p}
}

func (s *EBPFLiveSource) Next() (types.PacketEvent, bool) {
    ev, ok := <-s.ch
    return ev, ok
}
