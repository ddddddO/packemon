package egress_control

import (
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"github.com/vishvananda/netlink"
)

func PrepareDropingRSTPacket(nwInterface string) (*egress_packetObjects, *netlink.GenericQdisc, error) {
	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, nil, fmt.Errorf("removing memlock: %w", err)
	}

	// Load the compiled eBPF ELF and load it into the kernel.
	var objs egress_packetObjects
	if err := loadEgress_packetObjects(&objs, nil); err != nil {
		return nil, nil, fmt.Errorf("loading eBPF objects: %w", err)
	}

	qdisc, err := attachFilter(nwInterface, objs.egress_packetPrograms.ControlEgress)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to attach: %w", err)
	}

	return &objs, qdisc, nil
}

func Close(ebpfProg *egress_packetObjects, qdisc *netlink.GenericQdisc) error {
	ebpfProg.Close()
	// 以下で消しておかないと、再起動やtcコマンド使わない限り、RSTパケットがカーネルから送信されない状態になる
	if err := netlink.QdiscDel(qdisc); err != nil {
		return fmt.Errorf("Failed to QdiscDel. Please PC reboot... Error: %s\n", err)
	}
	return nil
}

// https://github.com/fedepaol/tc-return/blob/main/main.go
func attachFilter(attachTo string, program *ebpf.Program) (*netlink.GenericQdisc, error) {
	devID, err := net.InterfaceByName(attachTo)
	if err != nil {
		return nil, fmt.Errorf("could not get interface ID: %w", err)
	}

	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: devID.Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}

	err = netlink.QdiscReplace(qdisc)
	if err != nil {
		return nil, fmt.Errorf("could not get replace qdisc: %w", err)
	}

	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: devID.Index,
			Parent:    netlink.HANDLE_MIN_EGRESS,
			Handle:    1,
			Protocol:  unix.ETH_P_ALL,
		},
		Fd:           program.FD(),
		Name:         program.String(),
		DirectAction: true,
	}

	if err := netlink.FilterReplace(filter); err != nil {
		return nil, fmt.Errorf("failed to replace tc filter: %w", err)
	}

	return qdisc, nil
}
