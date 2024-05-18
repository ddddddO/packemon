package packemon

import (
	"golang.org/x/sys/unix"
)

type NetworkInterfaceForTCP struct {
	Socket int
}

func NewNetworkInterfaceForTCP(nwInterface string) (*NetworkInterfaceForTCP, error) {
	intf, err := getInterface(nwInterface)
	if err != nil {
		return nil, err
	}

	sock, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, unix.IPPROTO_TCP)
	if err != nil {
		return nil, err
	}

	if err := unix.BindToDevice(sock, intf.Name); err != nil {
		return nil, err
	}

	return &NetworkInterfaceForTCP{
		Socket: sock,
	}, nil
}

func (nwt *NetworkInterfaceForTCP) Connect(dstIPAddr []byte, dstPort uint16) error {
	addr := unix.SockaddrInet4{
		Addr: [4]byte{dstIPAddr[0], dstIPAddr[1], dstIPAddr[2], dstIPAddr[3]},
		Port: int(dstPort),
	}

	return unix.Connect(nwt.Socket, &addr)
}

func (nwt *NetworkInterfaceForTCP) Write(tcpPayload []byte) (int, error) {
	return unix.Write(nwt.Socket, tcpPayload)
}

func (nwt *NetworkInterfaceForTCP) Read(buf []byte) (int, error) {
	return unix.Read(nwt.Socket, buf)
}

func (nwt *NetworkInterfaceForTCP) Close() error {
	return unix.Close(nwt.Socket)
}
