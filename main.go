package main

import (
	"encoding/binary"
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

func main() {
	if err := run(); err != nil {
		panic(err)
	}
}

func run() error {
	interfaces, err := net.Interfaces()
	if err != nil {
		return err
	}

	var intf net.Interface
	for i := range interfaces {
		if interfaces[i].Name == "eth0" {
			intf = interfaces[i]
		}
	}

	fmt.Printf("Monitor interface: %v\n", intf)

	sock, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(hton(unix.ETH_P_ALL)))
	if err != nil {
		return err
	}

	addr := unix.SockaddrLinklayer{
		Protocol: hton(unix.ETH_P_ALL),
		Ifindex:  intf.Index,
	}

	if err := unix.Bind(sock, &addr); err != nil {
		return err
	}

	// if err := send(intf, sock, addr); err != nil {
	// 	return err
	// }

	if err := recieve(sock); err != nil {
		return err
	}

	return nil
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

func recieve(sock int) error {
	events := make([]unix.EpollEvent, 10)
	epollfd, err := unix.EpollCreate1(0)
	if err != nil {
		return err
	}

	if err := unix.EpollCtl(
		epollfd,
		unix.EPOLL_CTL_ADD,
		sock,
		&unix.EpollEvent{
			Events: unix.EPOLLIN,
			Fd:     int32(sock),
		},
	); err != nil {
		return err
	}

	for {
		fds, err := unix.EpollWait(epollfd, events, -1)
		if err != nil {
			return err
		}

		for i := 0; i < fds; i++ {
			if events[i].Fd != int32(sock) {
				continue
			}

			recieved := make([]byte, 1500)
			n, _, err := unix.Recvfrom(sock, recieved, 0)
			if err != nil {
				if n == -1 {
					continue
				}
				return err
			}

			// var typ uint16
			// if err := binary.Read(bytes.NewReader(recieved[12:14]), binary.BigEndian, &typ); err != nil {
			// 	panic(err)
			// }
			// 上のtypeとbinary.BigEndian.Uint16(recieved[12:14]) は同値
			// サンプルとしてunit testに置いておくあとで

			recievedEthernetFrame := &ethernetFrame{
				header: &ethernetHeader{
					dst: hardwareAddr(recieved[0:6]),
					src: hardwareAddr(recieved[6:12]),
					typ: binary.BigEndian.Uint16(recieved[12:14]),
				},
				data: recieved[14:],
			}

			HARDWAREADDR_BROADCAST := [6]uint8{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

			// 一旦 ARP request のみ
			switch recievedEthernetFrame.header.typ {
			case ETHER_TYPE_ARP:
				if recievedEthernetFrame.header.dst == HARDWAREADDR_BROADCAST {
					arp := &arp{
						hardwareType:       [2]uint8(recievedEthernetFrame.data[0:2]),
						protocolType:       binary.BigEndian.Uint16(recievedEthernetFrame.data[2:4]),
						hardwareAddrLength: recievedEthernetFrame.data[4],
						protocolLength:     recievedEthernetFrame.data[5],
						operation:          [2]uint8(recievedEthernetFrame.data[6:8]),

						senderHardwareAddr: hardwareAddr(recievedEthernetFrame.data[8:14]),
						senderIPAddr:       [4]uint8(recievedEthernetFrame.data[14:18]),

						targetHardwareAddr: hardwareAddr(recievedEthernetFrame.data[18:24]),
						targetIPAddr:       [4]uint8(recievedEthernetFrame.data[24:28]),
					}

					if err := view(recievedEthernetFrame, arp); err != nil {
						return err
					}
				}
			}
		}
	}

	return nil
}
