package capture

import (
    "bufio"
    "encoding/json"
    "io"

    "github.com/B3rt0oo/basic-intrusion-detection-system/internal/types"
)

// Source yields normalized packet events from some input.
type Source interface {
    Next() (types.PacketEvent, bool)
}

// JSONLSource reads PacketEvent values from newline-delimited JSON.
type JSONLSource struct {
    dec *json.Decoder
}

func NewJSONLSource(r io.Reader) *JSONLSource {
    // Scanner to normalize line buffering for Decoder. Decoder alone also works, but
    // wrapping ensures streaming behavior on large inputs.
    br := bufio.NewReader(r)
    return &JSONLSource{dec: json.NewDecoder(br)}
}

func (s *JSONLSource) Next() (types.PacketEvent, bool) {
    var ev types.PacketEvent
    if s.dec.More() {
        if err := s.dec.Decode(&ev); err != nil {
            // On decode error, stop the stream.
            return types.PacketEvent{}, false
        }
        return ev, true
    }
    // Attempt to read further tokens; if none, stop.
    var ev2 types.PacketEvent
    if err := s.dec.Decode(&ev2); err != nil {
        return types.PacketEvent{}, false
    }
    return ev2, true
}

