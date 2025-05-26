//go:build darwin || windows
// +build darwin windows

package debugging

func (dnw *debugNetworkInterface) SendHTTPSGetAfterTCP3wayAndTLShandshake(firsthopMACAddr [6]byte) error {
	return errNotSupportOnMac
}
