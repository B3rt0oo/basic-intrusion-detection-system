//go:build !ebpf

package capture

import "errors"

// NewEBPFSource is unavailable without the 'ebpf' build tag.
func NewEBPFSource(_ string) (*JSONLSource, error) {
    return nil, errors.New("ebpf capture not built; rebuild with -tags=ebpf")
}

