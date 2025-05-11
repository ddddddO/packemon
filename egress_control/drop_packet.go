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

	qdisc, err := attachFilterToEgress(nwInterface, objs.egress_packetPrograms.ControlEgress)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to attach: %w", err)
	}

	return &objs, qdisc, nil
}

// TODO: loadEgress_packetObjects とかと分けた方が良さそうだけど一旦 PrepareDropingRSTPacket の実行を前提とする
func PrepareAnalyzingIngressPackets(nwInterface string, ebpfProg *ebpf.Program) (*netlink.GenericQdisc, error) {
	qdisc, err := attachFilterToIngress(nwInterface, ebpfProg)
	if err != nil {
		return nil, fmt.Errorf("failed to attach: %w", err)
	}

	return qdisc, nil
}

type AnalyzedPackets struct {
	Sum uint64
}

func GetAnalyzedPackets(packetCount *ebpf.Map) (*AnalyzedPackets, error) {
	if packetCount == nil {
		return nil, fmt.Errorf("nil packetCount")
	}
	analyzed := &AnalyzedPackets{}
	key := uint32(0)
	err := packetCount.Lookup(key, &analyzed.Sum)
	return analyzed, err
}

func Close(ebpfProg *egress_packetObjects, qdisc1 *netlink.GenericQdisc, qdisc2 *netlink.GenericQdisc) error {
	if ebpfProg != nil {
		ebpfProg.Close()
	}

	if qdisc1 != nil {
		// 以下で消しておかないと、再起動やtcコマンド使わない限り、RSTパケットがカーネルから送信されない状態になる
		if err := netlink.QdiscDel(qdisc1); err != nil {
			return fmt.Errorf("Failed to QdiscDel. Please PC reboot... Error: %s\n", err)
		}
	}
	if qdisc2 != nil {
		if err := netlink.QdiscDel(qdisc2); err != nil {
			return fmt.Errorf("Failed to QdiscDel. Please PC reboot... Error: %s\n", err)
		}
	}

	return nil
}

// https://github.com/fedepaol/tc-return/blob/main/main.go
func attachFilterToEgress(attachTo string, program *ebpf.Program) (*netlink.GenericQdisc, error) {
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

func attachFilterToIngress(attachTo string, program *ebpf.Program) (*netlink.GenericQdisc, error) {
	devID, err := net.InterfaceByName(attachTo)
	if err != nil {
		return nil, fmt.Errorf("could not get interface ID: %w", err)
	}

	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: devID.Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_INGRESS,
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
			Parent:    netlink.HANDLE_MIN_INGRESS,
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
