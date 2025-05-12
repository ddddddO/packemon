package tc_program

import (
	"errors"
	"fmt"
	"io/fs"

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

func AddClsactQdisc(attachTo string) (*netlink.GenericQdisc, error) {
	iface, err := netlink.LinkByName(attachTo)
	if err != nil {
		return nil, err
	}

	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: iface.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}

	// ここはいい
	// if err := netlink.QdiscDel(qdisc); err != nil && !errors.Is(err, fs.ErrNotExist) {
	// 	return nil, fmt.Errorf("failed to QdiscDel: %w", err)
	// }

	if err := netlink.QdiscAdd(qdisc); err != nil {
		return nil, fmt.Errorf("failed to QdiscAdd: %w", err)
	}

	return qdisc, nil
}

func PrepareDropingRSTPacket(nwInterface string, objs *tc_programObjects) (*netlink.BpfFilter, error) {
	filter, err := attachFilterToEgress(nwInterface, objs.tc_programPrograms.ControlEgress)
	if err != nil {
		return nil, fmt.Errorf("failed to attach: %w", err)
	}

	return filter, nil
}

func PrepareAnalyzingIngressPackets(nwInterface string, objs *tc_programObjects) (*netlink.BpfFilter, error) {
	filter, err := attachFilterToIngress(nwInterface, objs.tc_programPrograms.ControlIngress)
	if err != nil {
		return nil, fmt.Errorf("failed to attach: %w", err)
	}

	return filter, nil
}

type AnalyzedPackets struct {
	Sum uint64
}

const (
	// ebpfプログラム側と合わせること。ただ、現状のWSL2だと同一mapに複数のkey指定できない？みたいだった
	SUM_COUNT_KEY = uint32(0)
)

func GetAnalyzedPackets(analysisMap *ebpf.Map) (*AnalyzedPackets, error) {
	if analysisMap == nil {
		return nil, fmt.Errorf("nil analysisMap")
	}

	analyzed := &AnalyzedPackets{}
	err := analysisMap.Lookup(SUM_COUNT_KEY, &analyzed.Sum)
	return analyzed, err
}

// TODO: err即returnではなくすべての処理してからerr返すようにしたほうがいいかも
func Close(ebpfProg *tc_programObjects, qdisc *netlink.GenericQdisc, filters ...*netlink.BpfFilter) error {
	if ebpfProg != nil {
		ebpfProg.Close()
	}

	for i, f := range filters {
		if f == nil {
			continue
		}
		if err := netlink.FilterDel(f); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("Failed to FilterDel (%d). Please PC reboot... Error: %s\n", i, err)
		}
	}

	if qdisc != nil {
		// 以下で消しておかないと、再起動やtcコマンド使わない限り、RSTパケットがカーネルから送信されない状態になる
		if err := netlink.QdiscDel(qdisc); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("Failed to QdiscDel. Please PC reboot... Error: %s\n", err)
		}
	}

	return nil
}

// https://github.com/fedepaol/tc-return/blob/main/main.go
func attachFilterToEgress(attachTo string, program *ebpf.Program) (*netlink.BpfFilter, error) {
	iface, err := netlink.LinkByName(attachTo)
	if err != nil {
		return nil, err
	}

	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: iface.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_EGRESS,
			Handle:    netlink.MakeHandle(0, 1),
			Protocol:  unix.ETH_P_ALL,
			Priority:  1,
		},
		Fd:           program.FD(),
		Name:         program.String(),
		DirectAction: true,
	}

	if err := netlink.FilterDel(filter); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("failed to FilterDel: %w", err)
	}

	if err := netlink.FilterAdd(filter); err != nil {
		return nil, fmt.Errorf("failed to FilterAdd: %w", err)
	}

	return filter, nil
}

func attachFilterToIngress(attachTo string, program *ebpf.Program) (*netlink.BpfFilter, error) {
	iface, err := netlink.LinkByName(attachTo)
	if err != nil {
		return nil, err
	}

	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: iface.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Handle:    netlink.MakeHandle(0, 2),
			Protocol:  unix.ETH_P_ALL,
			Priority:  1,
		},
		Fd:           program.FD(),
		Name:         program.String(),
		DirectAction: true,
	}

	if err := netlink.FilterDel(filter); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("failed to FilterDel: %w", err)
	}

	if err := netlink.FilterAdd(filter); err != nil {
		return nil, fmt.Errorf("failed to FilterAdd: %w", err)
	}

	return filter, nil
}
