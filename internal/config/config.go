package config

import (
    "encoding/json"
    "errors"
    "os"
    "time"
)

type Config struct {
    // Ingest
    Input struct {
        Type   string `json:"type"`   // "jsonl-stdin" or "pcap-live"
        Device string `json:"device"` // for pcap-live
        BPF    string `json:"bpf"`    // optional BPF filter
    } `json:"input"`

    // Port-scan detector settings
    PortScan struct {
        Enabled   bool          `json:"enabled"`
        Threshold int           `json:"threshold"`
        Window    time.Duration `json:"window"`
        MaxPerHost int          `json:"max_per_host"`
    } `json:"port_scan"`

    // Connection rate detector settings
    ConnRate struct {
        Enabled   bool          `json:"enabled"`
        Threshold int           `json:"threshold"`
        Window    time.Duration `json:"window"`
    } `json:"conn_rate"`

    // Alert sinks
    Alerts struct {
        Stdout bool   `json:"stdout"`
        File   string `json:"file"`
        Syslog bool   `json:"syslog"`
    } `json:"alerts"`

    // Signature rules (simple field matchers)
    Rules []Rule `json:"rules"`
}

type Rule struct {
    Name     string `json:"name"`
    Severity string `json:"severity"`
    Proto    string `json:"proto,omitempty"`
    SrcIP    string `json:"src_ip,omitempty"`
    DstIP    string `json:"dst_ip,omitempty"`
    DstPort  int    `json:"dst_port,omitempty"`
}

func Default() Config {
    var c Config
    c.Input.Type = "jsonl-stdin"
    c.PortScan.Enabled = true
    c.PortScan.Threshold = 10
    c.PortScan.Window = 60 * time.Second
    c.PortScan.MaxPerHost = 4096
    c.ConnRate.Enabled = true
    c.ConnRate.Threshold = 100
    c.ConnRate.Window = 10 * time.Second
    c.Alerts.Stdout = true
    c.Alerts.File = ""
    c.Alerts.Syslog = false
    c.Rules = nil
    return c
}

func Load(path string) (Config, error) {
    if path == "" {
        def := Default()
        return def, nil
    }
    b, err := os.ReadFile(path)
    if err != nil { return Config{}, err }
    if len(b) == 0 { return Config{}, errors.New("empty config file") }
    c := Default()
    if err := json.Unmarshal(b, &c); err != nil { return Config{}, err }
    return c, nil
}
