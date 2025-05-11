package tc_program

import (
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"github.com/vishvananda/netlink"
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

func PrepareDropingRSTPacket(nwInterface string, objs *tc_programObjects) (*netlink.GenericQdisc, error) {
	qdisc, err := attachFilterToEgress(nwInterface, objs.tc_programPrograms.ControlEgress)
	if err != nil {
		return nil, fmt.Errorf("failed to attach: %w", err)
	}

	return qdisc, nil
}

// TODO: loadEgress_packetObjects とかと分けた方が良さそうだけど一旦 PrepareDropingRSTPacket の実行を前提とする
func PrepareAnalyzingIngressPackets(nwInterface string, objs *tc_programObjects) (*netlink.GenericQdisc, error) {
	qdisc, err := attachFilterToIngress(nwInterface, objs.tc_programPrograms.ControlIngress)
	if err != nil {
		return nil, fmt.Errorf("failed to attach: %w", err)
	}

	return qdisc, nil
}

type AnalyzedPackets struct {
	Sum uint64
}

const (
	// ebpfプログラム側と合わせること。ただ、現状のWSL2だと同一mapに複数のkey指定できない？みたいだった
	SUM_COUNT_KEY = uint32(0)
)

func GetAnalyzedPackets(packetCount *ebpf.Map) (*AnalyzedPackets, error) {
	if packetCount == nil {
		return nil, fmt.Errorf("nil packetCount")
	}

	analyzed := &AnalyzedPackets{}
	err := packetCount.Lookup(SUM_COUNT_KEY, &analyzed.Sum)
	return analyzed, err
}

func Close(ebpfProg *tc_programObjects, qdiscs ...*netlink.GenericQdisc) error {
	if ebpfProg != nil {
		ebpfProg.Close()
	}

	for _, q := range qdiscs {
		if q != nil {
			// 以下で消しておかないと、再起動やtcコマンド使わない限り、RSTパケットがカーネルから送信されない状態になる
			if err := netlink.QdiscDel(q); err != nil {
				return fmt.Errorf("Failed to QdiscDel. Please PC reboot... Error: %s\n", err)
			}
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
