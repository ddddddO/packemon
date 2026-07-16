//go:build darwin || windows
// +build darwin windows

package tc_program

import (
	"fmt"

	"github.com/cilium/ebpf/link"
)

func InitializeTCProgram() (*tc_programObjects, error) {
	return nil, errNotSupportOnMac("InitializeTCProgram")
}

func PrepareDropingRSTPacket(nwInterface string, objs *tc_programObjects) (link.Link, error) {
	return nil, errNotSupportOnMac("PrepareDropingRSTPacket")
}

func PrepareAnalyzingIngressPackets(nwInterface string, objs *tc_programObjects) (link.Link, error) {
	return nil, errNotSupportOnMac("PrepareAnalyzingIngressPackets")
}

func Close(ebpfProg *tc_programObjects, links ...link.Link) error {
	return nil
}

func errNotSupportOnMac(msg string) error {
	return fmt.Errorf("not support on mac: %s", msg)
}
