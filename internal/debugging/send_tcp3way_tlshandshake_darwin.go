//go:build darwin
// +build darwin

package debugging

func (dnw *debugNetworkInterface) SendTCP3wayAndTLShandshake(firsthopMACAddr [6]byte) error {
	return errNotSupportOnMac
}
