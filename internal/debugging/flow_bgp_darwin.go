//go:build darwin
// +build darwin

package debugging

func (dnw *debugNetworkInterface) FlowBGP() error {
	return errNotSupportOnMac
}
