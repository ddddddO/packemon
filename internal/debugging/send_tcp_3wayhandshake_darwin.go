//go:build darwin
// +build darwin

package debugging

func (dnw *debugNetworkInterface) SendTCP3wayhandshake(firsthopMACAddr [6]byte) error {
	return errNotSupportOnMac
}
