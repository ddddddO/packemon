package debugging

import (
	"encoding/binary"
	"log"

	p "github.com/ddddddO/packemon"
	"golang.org/x/sys/unix"
)

type debugNetworkInterface struct {
	*p.NetworkInterface
}

func NewDebugNetworkInterface(netIF *p.NetworkInterface) *debugNetworkInterface {
	return &debugNetworkInterface{
		NetworkInterface: netIF,
	}
}

func (dnw *debugNetworkInterface) Recieve() error {
	log.Println("in Recive")

	epollfd, err := unix.EpollCreate1(0)
	if err != nil {
		return err
	}

	if err := unix.EpollCtl(
		epollfd,
		unix.EPOLL_CTL_ADD,
		dnw.Socket,
		&unix.EpollEvent{
			Events: unix.EPOLLIN,
			Fd:     int32(dnw.Socket),
		},
	); err != nil {
		return err
	}

	events := make([]unix.EpollEvent, 10)
	for {
		log.Println("in loop")

		fds, err := unix.EpollWait(epollfd, events, -1)
		if err != nil {
			return err
		}

		log.Printf("fds length: %d\n", fds)

		for i := 0; i < fds; i++ {
			if events[i].Fd == int32(dnw.Socket) {
				recieved := make([]byte, 1500)
				n, _, err := unix.Recvfrom(dnw.Socket, recieved, 0)
				if err != nil {
					if n == -1 {
						log.Println("-1 unix.Recvfrom")
						continue
					}
					return err
				}

				log.Println("recieved")

				ethernetFrame := &p.EthernetFrame{
					Header: &p.EthernetHeader{
						Dst: p.HardwareAddr(recieved[0:6]),
						Src: p.HardwareAddr(recieved[6:12]),
						Typ: binary.BigEndian.Uint16(recieved[12:14]), // タグVLANだとズレる
					},
					Data: recieved[14:],
				}

				HARDWAREADDR_BROADCAST := p.HardwareAddr([6]uint8{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})

				switch ethernetFrame.Header.Typ {
				case p.ETHER_TYPE_ARP:
					switch ethernetFrame.Header.Dst {
					case p.HardwareAddr(dnw.Intf.HardwareAddr), HARDWAREADDR_BROADCAST:
						log.Println("recieved ARP")

						arp := p.ParsedARP(ethernetFrame.Data)

						// dnw.PassiveCh <- &p.Passive{
						// 	EthernetFrame: ethernetFrame,
						// 	ARP:           arp,
						// }
						_ = arp
					}
				case p.ETHER_TYPE_IPv4:
					switch ethernetFrame.Header.Dst {
					case p.HardwareAddr(dnw.Intf.HardwareAddr), HARDWAREADDR_BROADCAST:
						log.Println("recieved IPv4")

						ipv4 := &p.IPv4{
							Version:        ethernetFrame.Data[0] >> 4,
							Ihl:            ethernetFrame.Data[0] << 4 >> 4,
							Tos:            ethernetFrame.Data[1],
							TotalLength:    binary.BigEndian.Uint16(ethernetFrame.Data[2:4]),
							Identification: binary.BigEndian.Uint16(ethernetFrame.Data[4:6]),
							Flags:          ethernetFrame.Data[6],
							FragmentOffset: binary.BigEndian.Uint16(ethernetFrame.Data[6:8]),
							Ttl:            ethernetFrame.Data[8],
							Protocol:       ethernetFrame.Data[9],
							HeaderChecksum: binary.BigEndian.Uint16(ethernetFrame.Data[10:12]),
							SrcAddr:        binary.BigEndian.Uint32(ethernetFrame.Data[12:16]),
							DstAddr:        binary.BigEndian.Uint32(ethernetFrame.Data[16:20]),
						}

						// switch ipv4.DstAddr {
						// case dnw.IPAdder:
						// 	dnw.PassiveCh <- &p.Passive{
						// 		EthernetFrame: ethernetFrame,
						// 		IPv4:          ipv4,
						// 	}
						// }
						_ = ipv4
					}
				}

				log.Println("end inner loop")
			}
		}
	}

	return nil
}
