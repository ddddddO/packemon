//go:build darwin
// +build darwin

package tc_program

import (
	"fmt"

	"github.com/vishvananda/netlink"
)

func InitializeTCProgram() (*tc_programObjects, error) {
	return nil, errNotSupportOnMac("InitializeTCProgram")
}

func AddClsactQdisc(attachTo string) (*netlink.GenericQdisc, error) {
	return nil, errNotSupportOnMac("AddClsactQdisc")
}

func PrepareDropingRSTPacket(nwInterface string, objs *tc_programObjects) (*netlink.BpfFilter, error) {
	return nil, errNotSupportOnMac("PrepareDropingRSTPacket")
}

func PrepareAnalyzingIngressPackets(nwInterface string, objs *tc_programObjects) (*netlink.BpfFilter, error) {
	return nil, errNotSupportOnMac("PrepareAnalyzingIngressPackets")
}

func Close(ebpfProg *tc_programObjects, qdisc *netlink.GenericQdisc, filters ...*netlink.BpfFilter) error {
	return nil
}

func errNotSupportOnMac(msg string) error {
	return fmt.Errorf("not support on mac: %s", msg)
}
