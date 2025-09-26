//go:build !pcap

package capture

import "errors"

// NewLivePCAPSource is unavailable without the 'pcap' build tag.
func NewLivePCAPSource(device, bpf string) (*JSONLSource, error) {
    return nil, errors.New("pcap capture not built; rebuild with -tags=pcap")
}

