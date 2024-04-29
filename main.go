package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"net"

	"github.com/rivo/tview"
	"golang.org/x/sys/unix"
)

func main() {
	var wantSend bool
	flag.BoolVar(&wantSend, "send", false, "Send packet")
	flag.Parse()

	if err := run(wantSend); err != nil {
		panic(err)
	}
}

// TODO:
// - 以下グローバルなところ何とかしたい
// - 外部ライブラリへの依存は局所的にしたい
var (
	globalTviewApp  *tview.Application
	globalTviewGrid *tview.Grid
)

func run(wantSend bool) error {
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

	if wantSend {
		// arp := newARP()
		// dst := hardwareAddr([6]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0x12})
		// src := hardwareAddr(intf.HardwareAddr)
		// ethernetFrame := newEthernetFrame(dst, src, ETHER_TYPE_ARP, arp.toBytes())
		// return send(ethernetFrame, sock, addr)

		// icmp := newICMP()
		// ipv4 := newIPv4()
		// ipv4.data = icmp.toBytes()

		// fmt.Printf("ICMP fata len: %d\n", len(ipv4.data))

		// dst := hardwareAddr([6]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0x12})
		// src := hardwareAddr(intf.HardwareAddr)
		// ethernetFrame := newEthernetFrame(dst, src, ETHER_TYPE_IPv4, ipv4.toBytes())
		// return send(ethernetFrame, sock, addr)

		return form(sendForForm(sock, addr)) // Form のアクションで 送信した方が良さそうなのでこの形
	} else {
		globalTviewGrid = tview.NewGrid()
		globalTviewGrid.Box = tview.NewBox().SetBorder(true).SetTitle(" Packemon ")
		globalTviewApp = tview.NewApplication()
		viewersCh := make(chan []viewer, 10)

		go updateView(viewersCh)
		go recieve(sock, intf, viewersCh)
		return globalTviewApp.SetRoot(globalTviewGrid, true).Run()
	}
}

func hton(i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
}

func sendForForm(sock int, addr unix.SockaddrLinklayer) func(*ethernetFrame) error {
	return func(ethernetFrame *ethernetFrame) error {
		return send(ethernetFrame, sock, addr)
	}
}

func send(ethernetFrame *ethernetFrame, sock int, addr unix.SockaddrLinklayer) error {
	return unix.Sendto(sock, ethernetFrame.toBytes(), 0, &addr)
}

func recieve(sock int, intf net.Interface, viewersCh chan<- []viewer) error {
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

	events := make([]unix.EpollEvent, 10)
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

			recievedEthernetFrame := &ethernetFrame{
				header: &ethernetHeader{
					dst: hardwareAddr(recieved[0:6]),
					src: hardwareAddr(recieved[6:12]),
					typ: binary.BigEndian.Uint16(recieved[12:14]), // タグVLANだとズレる
				},
				data: recieved[14:],
			}

			HARDWAREADDR_BROADCAST := [6]uint8{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

			switch recievedEthernetFrame.header.typ {
			case ETHER_TYPE_ARP:
				switch recievedEthernetFrame.header.dst {
				case hardwareAddr(intf.HardwareAddr), HARDWAREADDR_BROADCAST:
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

					viewersCh <- []viewer{recievedEthernetFrame, arp}
				}
			case ETHER_TYPE_IPv4:
				switch recievedEthernetFrame.header.dst {
				case hardwareAddr(intf.HardwareAddr), HARDWAREADDR_BROADCAST:
					// for debug. 以下外すと結構受信しちゃうから動作確認は↓をコメントイン
					// if recievedEthernetFrame.header.src == HARDWAREADDR_BROADCAST {
					ipv4 := &ipv4{
						version:        recievedEthernetFrame.data[0] >> 4,
						ihl:            recievedEthernetFrame.data[0] << 4 >> 4,
						tos:            recievedEthernetFrame.data[1],
						totalLength:    binary.BigEndian.Uint16(recievedEthernetFrame.data[2:4]),
						identification: binary.BigEndian.Uint16(recievedEthernetFrame.data[4:6]),
						flags:          recievedEthernetFrame.data[6],
						fragmentOffset: binary.BigEndian.Uint16(recievedEthernetFrame.data[6:8]),
						ttl:            recievedEthernetFrame.data[8],
						protocol:       recievedEthernetFrame.data[9],
						headerChecksum: binary.BigEndian.Uint16(recievedEthernetFrame.data[10:12]),
						srcAddr:        binary.BigEndian.Uint32(recievedEthernetFrame.data[12:16]),
						dstAddr:        binary.BigEndian.Uint32(recievedEthernetFrame.data[16:20]),
					}

					viewersCh <- []viewer{recievedEthernetFrame, ipv4}
					// }
				}
			}
		}
	}

	return nil
}
