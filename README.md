# Basic Intrusion Detection System (IDS)

A modernized IDS with a clear architecture and tests. The repository now includes:

- A Go implementation that follows clean package boundaries and adds a tested port-scan detector and detection pipeline.
- The original Python proof‑of‑concept (Scapy) for reference.

This is the first step in a professional‑grade IDS roadmap: introducing a maintainable core, unit tests, and a CLI. Next iterations will add packet capture via pcap/eBPF, signature rules, anomaly models, alerting backends, and CI.

---

## Go Implementation

Layout:

- `cmd/ids` — thin CLI reading PacketEvent JSON from stdin and emitting Alert JSON.
- `internal/detect` — detection engines (port scan in this iteration).
- `internal/detect` — detection engines: port scan, connection-rate, signatures.
- `internal/detect` — DNS anomaly detector (unique subdomains, long names, rate).
 - `internal/detect` — DNS anomaly detector (unique subdomains, long names, rate, NXDOMAIN ratio, entropy).
- `internal/pipeline` — event fan‑out and alert aggregation.
- `internal/types` — shared data types.

Build (Go 1.22+):

```bash
cd external/basic-ids
go build ./cmd/ids
```

Run examples:

```bash
echo '{"ts":"2024-01-01T00:00:00Z","src_ip":"1.2.3.4","dst_ip":"10.0.0.1","dst_port":22,"proto":"tcp"}' \
  '{"ts":"2024-01-01T00:00:01Z","src_ip":"1.2.3.4","dst_ip":"10.0.0.1","dst_port":80,"proto":"tcp"}' \
  '{"ts":"2024-01-01T00:00:02Z","src_ip":"1.2.3.4","dst_ip":"10.0.0.1","dst_port":443,"proto":"tcp"}' \
  | ./ids -config config.example.json

Or, with CLI defaults (stdout alerts, defaults enabled):

```bash
echo '{"src_ip":"1.2.3.4","dst_ip":"10.0.0.1","dst_port":22,"proto":"tcp"}
{"src_ip":"1.2.3.4","dst_ip":"10.0.0.1","dst_port":80,"proto":"tcp"}
{"src_ip":"1.2.3.4","dst_ip":"10.0.0.1","dst_port":443,"proto":"tcp"}' | ./ids
```

Config file (JSON): see `config.example.json`.

Live capture (optional): build with pcap tag and configure input:

```bash
go build -tags=pcap ./cmd/ids
./ids -config config.example.json
```

Where config includes:

```json
{
  "input": { "type": "pcap-live", "device": "eth0", "bpf": "tcp or udp" }
}

eBPF live capture (advanced):

```bash
# Build ebpf-enabled binary
go build -tags=ebpf ./cmd/ids

# Build BPF object (requires clang/llvm)
cd bpf && make && cd ..

# Configure and run (requires privileges)
jq '.input={"type":"ebpf-live","program":"./bpf/ids_bpf.o"}' config.example.json > /tmp/ids-ebpf.json
sudo ./ids -config /tmp/ids-ebpf.json
```

Note: the included BPF program is a minimal skeleton; attach points to push events into the ring buffer need to be implemented for production use.

System prerequisites for live capture:

- Debian/Ubuntu: `sudo apt-get install libpcap-dev` (build) and `libpcap0.8` (runtime)
- Alpine: `apk add libpcap-dev` (build) and `libpcap` (runtime)
- macOS: Xcode CLT provides libpcap; Homebrew alternative: `brew install libpcap`

Docker build and run:

```bash
# Default (JSONL stdin capture)
docker build -t ids:latest .

# With live capture support
docker build -t ids:pcap --build-arg BUILD_TAGS=pcap .

# Run with live capture on host network (Linux), privileged to sniff
docker run --rm --net=host --cap-add NET_RAW --cap-add NET_ADMIN \
  -v $(pwd)/config.example.json:/etc/ids/config.json:ro \
  ids:pcap -config /etc/ids/config.json
```
Flags:

- `-port-scan-threshold` — unique destination ports to trigger alert (default 10)
- `-window` — sliding window in seconds (default 60)
- `-quiet` — suppress non‑alert output

Metrics endpoint:

```bash
./ids -config config.example.json -metrics-listen :9090
# scrape http://localhost:9090/metrics
```

DNS anomaly and signatures:

- dns_anomaly config tunes window, unique subdomain threshold, long name length, and per-source rate.
- Signatures support CIDR, port ranges, and DNS matchers (suffix, regex, qtype).

Linting and coverage locally:

```bash
golangci-lint run
go test -race -cover ./...
# enforce >= 80% for detect package
go test -race -coverprofile=detect.cov ./internal/detect && go tool cover -func=detect.cov | tail -1
```

---

## Python POC

The original Scapy‑based script remains available at `basic_intrusion_detection_system.py`. It detects basic port scans and logs to `alerts.log`.
