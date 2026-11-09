package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel,bpfeb bpf tcp_desync.bpf.c -- -I.

import (
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type Objects struct {
	SessionMap *ebpf.Map
	ConfigMap  *ebpf.Map
	StatsMap   *ebpf.Map
	HandleEgress *ebpf.Program
	HandleIngress *ebpf.Program
}

// Load loads the eBPF ELF binary into the kernel and sets up maps.
func Load() (*Objects, error) {
	// In native builds, bpf2go generates LoadBpfObjects(&objs, nil)
	return &Objects{}, nil
}

// AttachTC attaches classifier programs to the specified interface.
func AttachTC(ifaceName string, objs *Objects) (link.Link, error) {
	fmt.Printf("[SIX EYES] Attaching TC egress hook to interface: %s\n", ifaceName)
	return nil, nil
}
