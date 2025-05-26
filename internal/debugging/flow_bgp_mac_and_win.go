//go:build darwin || windows
// +build darwin windows

package debugging

func (dnw *debugNetworkInterface) FlowBGP() error {
	return errNotSupportOnMac
}
