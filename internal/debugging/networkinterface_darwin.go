//go:build darwin
// +build darwin

package debugging

import (
	"fmt"

	p "github.com/ddddddO/packemon"
)

var errNotSupportOnMac = fmt.Errorf("not support on mac")

type debugNetworkInterface struct {
	*p.NetworkInterface
}

func NewDebugNetworkInterface(netIF *p.NetworkInterface) *debugNetworkInterface {
	return &debugNetworkInterface{
		NetworkInterface: netIF,
	}
}

func (dnw *debugNetworkInterface) Recieve() error {
	return errNotSupportOnMac
}
