package alert

import (
    "bufio"
    "encoding/json"
    "fmt"
    "os"
    "log/syslog"

    "github.com/B3rt0oo/basic-intrusion-detection-system/internal/types"
)

// Sink consumes alerts (e.g., stdout, file, webhook).
type Sink interface {
    Emit(a types.Alert) error
    Close() error
}

// StdoutSink prints alerts as JSON lines to stdout.
type StdoutSink struct {}

func (StdoutSink) Emit(a types.Alert) error {
    b, err := json.Marshal(a)
    if err != nil { return err }
    fmt.Println(string(b))
    return nil
}
func (StdoutSink) Close() error { return nil }

// FileSink appends JSONL alerts to a file.
type FileSink struct {
    f *os.File
    w *bufio.Writer
}

func NewFileSink(path string) (*FileSink, error) {
    f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
    if err != nil { return nil, err }
    return &FileSink{f: f, w: bufio.NewWriter(f)}, nil
}

func (s *FileSink) Emit(a types.Alert) error {
    b, err := json.Marshal(a)
    if err != nil { return err }
    if _, err := s.w.Write(b); err != nil { return err }
    if err := s.w.WriteByte('\n'); err != nil { return err }
    return s.w.Flush()
}

func (s *FileSink) Close() error {
    if s.w != nil { _ = s.w.Flush() }
    if s.f != nil { return s.f.Close() }
    return nil
}

// SyslogSink writes alerts to local syslog as JSON.
type SyslogSink struct { w *syslog.Writer }

func NewSyslogSink(tag string) (*SyslogSink, error) {
    w, err := syslog.New(syslog.LOG_ALERT|syslog.LOG_DAEMON, tag)
    if err != nil { return nil, err }
    return &SyslogSink{w: w}, nil
}

func (s *SyslogSink) Emit(a types.Alert) error {
    b, err := json.Marshal(a)
    if err != nil { return err }
    return s.w.Alert(string(b))
}

func (s *SyslogSink) Close() error { if s.w != nil { return s.w.Close() }; return nil }
