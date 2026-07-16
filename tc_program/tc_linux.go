//go:build linux
// +build linux

package tc_program

import (
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func InitializeTCProgram() (*tc_programObjects, error) {
	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("removing memlock: %w", err)
	}

	// Load the compiled eBPF ELF and load it into the kernel.
	var objs tc_programObjects
	if err := loadTc_programObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("loading eBPF objects: %w", err)
	}

	return &objs, nil
}

func PrepareDropingRSTPacket(nwInterface string, objs *tc_programObjects) (link.Link, error) {
	iface, err := net.InterfaceByName(nwInterface)
	if err != nil {
		return nil, err
	}

	return link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   objs.ControlEgress,
		Attach:    ebpf.AttachTCXEgress,
	})
}

func PrepareAnalyzingIngressPackets(nwInterface string, objs *tc_programObjects) (link.Link, error) {
	iface, err := net.InterfaceByName(nwInterface)
	if err != nil {
		return nil, err
	}

	return link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   objs.ControlIngress,
		Attach:    ebpf.AttachTCXIngress,
	})
}

// TODO: err即returnではなくすべての処理してからerr返すようにしたほうがいいかも
func Close(ebpfProg *tc_programObjects, links ...link.Link) error {
	if ebpfProg != nil {
		ebpfProg.Close()
	}
	for _, l := range links {
		l.Close()
	}

	return nil
}
