package main

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

func main() {
	interfaces, err := net.Interfaces()
	if err != nil {
		panic(err)
	}

	fmt.Println("Interfaces")

	var intf net.Interface
	for i := range interfaces {
		fmt.Println(interfaces[i])

		if interfaces[i].Name == "eth0" {
			intf = interfaces[i]
		}
	}

	// fmt.Println(intf)
	fmt.Println(unix.ETH_P_ALL)
	fmt.Println(hton(unix.ETH_P_ALL))

	sock, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(hton(unix.ETH_P_ALL)))
	if err != nil {
		panic(err)
	}

	addr := unix.SockaddrLinklayer{
		Protocol: hton(unix.ETH_P_ALL),
		Ifindex:  intf.Index,
	}

	if err := unix.Bind(sock, &addr); err != nil {
		panic(err)
	}

	if err := send(intf, sock, addr); err != nil {
		panic(err)
	}

}

func hton(i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
}

func send(intf net.Interface, sock int, addr unix.SockaddrLinklayer) error {
	dst := [6]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0x11}
	// payload := []byte("Yeah!!!!!")
	arp := newARP()
	payload := arp.toBytes()
	frame := newEthernetFrame(dst, intf.HardwareAddr, ETHER_TYPE_ARP, payload)

	return unix.Sendto(sock, frame.toBytes(), 0, &addr)
}
