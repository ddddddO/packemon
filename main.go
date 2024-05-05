package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"strings"

	"github.com/rivo/tview"
	"golang.org/x/sys/unix"
)

func main() {
	var wantSend bool
	flag.BoolVar(&wantSend, "send", false, "Send packet")
	var protocol string
	flag.StringVar(&protocol, "proto", "", "Specify either 'arp', 'icmp', 'tcp', 'dns' or 'http'.")
	flag.Parse()

	if err := run(wantSend, protocol); err != nil {
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

func run(wantSend bool, protocol string) error {
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
	DEFAULT_MAC_DESTINATION = fmt.Sprintf("0x%s", strings.ReplaceAll(intf.HardwareAddr.String(), ":", ""))
	DEFAULT_MAC_SOURCE = DEFAULT_MAC_DESTINATION
	DEFAULT_ARP_SENDER_MAC = DEFAULT_MAC_SOURCE

	fmt.Printf("Monitor interface: %v\n", intf)
	ipAddr, err := intf.Addrs()
	if err != nil {
		return err
	}
	DEFAULT_IP_SOURCE = strings.Split(ipAddr[0].String(), "/")[0]
	DEFAULT_IP_DESTINATION = DEFAULT_IP_SOURCE
	DEFAULT_ARP_SENDER_IP = DEFAULT_IP_SOURCE
	DEFAULT_ARP_TARGET_IP = DEFAULT_ARP_SENDER_IP

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

	// PC再起動とかでdstのMACアドレス変わるみたい。以下で調べてdst正しいのにする
	// $ ip route
	// $ arp xxx.xx.xxx.1
	firsthopMACAddr := [6]byte{0x01, 0x00, 0x5e, 0x7f, 0xff, 0xfa}

	if wantSend {
		switch protocol {
		case "arp":
			return sendARPrequest(sock, addr, intf, firsthopMACAddr)
		case "icmp":
			return sendICMPechoRequest(sock, addr, intf, firsthopMACAddr)
		case "tcp":
			return sendTCPsyn(sock, addr, intf, firsthopMACAddr)
		case "dns":
			return sendDNSquery(sock, addr, intf, firsthopMACAddr)
		case "http":
			return sendHTTPget(sock, addr, intf, firsthopMACAddr)
		default:
			return form(sendForForm(sock, addr)) // Form のアクションで 送信した方が良さそうなのでこの形
		}
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

func sendARPrequest(sock int, addr unix.SockaddrLinklayer, intf net.Interface, firsthopMACAddr [6]byte) error {
	arp := NewARP()
	dst := HardwareAddr(firsthopMACAddr)
	src := HardwareAddr(intf.HardwareAddr)
	ethernetFrame := NewEthernetFrame(dst, src, ETHER_TYPE_ARP, arp.Bytes())
	return send(ethernetFrame, sock, addr)
}

func sendICMPechoRequest(sock int, addr unix.SockaddrLinklayer, intf net.Interface, firsthopMACAddr [6]byte) error {
	icmp := NewICMP()
	ipv4 := NewIPv4(IPv4_PROTO_ICMP, 0xa32b661d) // dst: 163.43.102.29 = tools.m-bsys.com
	ipv4.Data = icmp.Bytes()
	ipv4.CalculateTotalLength()
	ipv4.CalculateChecksum()
	dst := HardwareAddr(firsthopMACAddr)
	src := HardwareAddr(intf.HardwareAddr)
	ethernetFrame := NewEthernetFrame(dst, src, ETHER_TYPE_IPv4, ipv4.Bytes())
	return send(ethernetFrame, sock, addr)
}

func sendDNSquery(sock int, addr unix.SockaddrLinklayer, intf net.Interface, firsthopMACAddr [6]byte) error {
	dns := &DNS{
		TransactionID: 0x1234,
		Flags:         0x0100, // standard query
		Questions:     0x0001,
		AnswerRRs:     0x0000,
		AuthorityRRs:  0x0000,
		AdditionalRRs: 0x0000,
		Queries: &Queries{
			Typ:   0x0001, // A
			Class: 0x0001, // IN
		},
	}
	// dns.domain("github.com")
	dns.Domain("go.dev")
	udp := &udp{
		srcPort:  0x0401, // 1025
		dstPort:  0x0035, // 53
		length:   0x0000,
		checksum: 0x0000,
	}
	udp.data = dns.Bytes()
	udp.len()
	ipv4 := NewIPv4(IPv4_PROTO_UDP, 0x08080808) // 8.8.8.8 = DNSクエリ用
	ipv4.Data = udp.toBytes()
	ipv4.CalculateTotalLength()
	ipv4.CalculateChecksum()
	dst := HardwareAddr(firsthopMACAddr)
	src := HardwareAddr(intf.HardwareAddr)
	ethernetFrame := NewEthernetFrame(dst, src, ETHER_TYPE_IPv4, ipv4.Bytes())
	return send(ethernetFrame, sock, addr)
}

func sendTCPsyn(sock int, addr unix.SockaddrLinklayer, intf net.Interface, firsthopMACAddr [6]byte) error {
	tcp := newTCPSyn()
	ipv4 := NewIPv4(IPv4_PROTO_TCP, 0xa32b661d) // 163.43.102.29 = tools.m-bsys.com こちらで、ack返ってきた
	// https://atmarkit.itmedia.co.jp/ait/articles/0401/29/news080_2.html
	// 「「チェックサム」フィールド：16bit幅」
	tcp.checksum = func() uint16 {
		pseudoTCPHeader := func() []byte {
			var buf bytes.Buffer
			b := make([]byte, 4)
			binary.BigEndian.PutUint32(b, ipv4.SrcAddr)
			buf.Write(b)
			b = make([]byte, 4)
			binary.BigEndian.PutUint32(b, ipv4.DstAddr)
			buf.Write(b)
			padding := byte(0x00)
			buf.WriteByte(padding)
			buf.WriteByte(ipv4.Protocol)
			b = make([]byte, 2)
			binary.BigEndian.PutUint16(b, uint16(len(tcp.toBytes())))
			buf.Write(b)
			return buf.Bytes()
		}()
		var forTCPChecksum bytes.Buffer
		forTCPChecksum.Write(pseudoTCPHeader)
		forTCPChecksum.Write(tcp.toBytes())
		return binary.BigEndian.Uint16(tcp.checkSum(forTCPChecksum.Bytes()))
	}()
	ipv4.Data = tcp.toBytes()
	ipv4.CalculateTotalLength()
	ipv4.CalculateChecksum()
	dst := HardwareAddr(firsthopMACAddr)
	src := HardwareAddr(intf.HardwareAddr)
	ethernetFrame := NewEthernetFrame(dst, src, ETHER_TYPE_IPv4, ipv4.Bytes())
	return send(ethernetFrame, sock, addr)
}

func sendHTTPget(sock int, addr unix.SockaddrLinklayer, intf net.Interface, firsthopMACAddr [6]byte) error {
	http := NewHTTP()
	tcp := newTCPWithData(http.Bytes())
	ipv4 := NewIPv4(IPv4_PROTO_TCP, 0x88bb0609) // 136.187.6.9 = research.nii.ac.jp
	// https://atmarkit.itmedia.co.jp/ait/articles/0401/29/news080_2.html
	// 「「チェックサム」フィールド：16bit幅」
	tcp.checksum = func() uint16 {
		pseudoTCPHeader := func() []byte {
			var buf bytes.Buffer
			b := make([]byte, 4)
			binary.BigEndian.PutUint32(b, ipv4.SrcAddr)
			buf.Write(b)
			b = make([]byte, 4)
			binary.BigEndian.PutUint32(b, ipv4.DstAddr)
			buf.Write(b)
			padding := byte(0x00)
			buf.WriteByte(padding)
			buf.WriteByte(ipv4.Protocol)
			b = make([]byte, 2)
			binary.BigEndian.PutUint16(b, uint16(len(tcp.toBytes())))
			buf.Write(b)
			return buf.Bytes()
		}()
		var forTCPChecksum bytes.Buffer
		forTCPChecksum.Write(pseudoTCPHeader)
		forTCPChecksum.Write(tcp.toBytes())
		return binary.BigEndian.Uint16(tcp.checkSum(forTCPChecksum.Bytes()))
	}()
	ipv4.Data = tcp.toBytes()
	ipv4.CalculateTotalLength()
	ipv4.CalculateChecksum()
	dst := HardwareAddr(firsthopMACAddr)
	src := HardwareAddr(intf.HardwareAddr)
	ethernetFrame := NewEthernetFrame(dst, src, ETHER_TYPE_IPv4, ipv4.Bytes())
	return send(ethernetFrame, sock, addr)
}

func sendForForm(sock int, addr unix.SockaddrLinklayer) func(*EthernetFrame) error {
	return func(ethernetFrame *EthernetFrame) error {
		return send(ethernetFrame, sock, addr)
	}
}

func send(ethernetFrame *EthernetFrame, sock int, addr unix.SockaddrLinklayer) error {
	return unix.Sendto(sock, ethernetFrame.Bytes(), 0, &addr)
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
			if events[i].Fd == int32(sock) {
				recieved := make([]byte, 1500)
				n, _, err := unix.Recvfrom(sock, recieved, 0)
				if err != nil {
					if n == -1 {
						continue
					}
					return err
				}

				recievedEthernetFrame := &EthernetFrame{
					Header: &EthernetHeader{
						Dst: HardwareAddr(recieved[0:6]),
						Src: HardwareAddr(recieved[6:12]),
						Typ: binary.BigEndian.Uint16(recieved[12:14]), // タグVLANだとズレる
					},
					Data: recieved[14:],
				}

				HARDWAREADDR_BROADCAST := [6]uint8{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

				switch recievedEthernetFrame.Header.Typ {
				case ETHER_TYPE_ARP:
					switch recievedEthernetFrame.Header.Dst {
					case HardwareAddr(intf.HardwareAddr), HARDWAREADDR_BROADCAST:
						arp := &ARP{
							HardwareType:       [2]uint8(recievedEthernetFrame.Data[0:2]),
							ProtocolType:       binary.BigEndian.Uint16(recievedEthernetFrame.Data[2:4]),
							HardwareAddrLength: recievedEthernetFrame.Data[4],
							ProtocolLength:     recievedEthernetFrame.Data[5],
							Operation:          [2]uint8(recievedEthernetFrame.Data[6:8]),

							SenderHardwareAddr: HardwareAddr(recievedEthernetFrame.Data[8:14]),
							SenderIPAddr:       [4]uint8(recievedEthernetFrame.Data[14:18]),

							TargetHardwareAddr: HardwareAddr(recievedEthernetFrame.Data[18:24]),
							TargetIPAddr:       [4]uint8(recievedEthernetFrame.Data[24:28]),
						}

						viewersCh <- []viewer{recievedEthernetFrame, arp}
					}
				case ETHER_TYPE_IPv4:
					switch recievedEthernetFrame.Header.Dst {
					case HardwareAddr(intf.HardwareAddr), HARDWAREADDR_BROADCAST:
						ipv4 := &IPv4{
							Version:        recievedEthernetFrame.Data[0] >> 4,
							Ihl:            recievedEthernetFrame.Data[0] << 4 >> 4,
							Tos:            recievedEthernetFrame.Data[1],
							TotalLength:    binary.BigEndian.Uint16(recievedEthernetFrame.Data[2:4]),
							Identification: binary.BigEndian.Uint16(recievedEthernetFrame.Data[4:6]),
							Flags:          recievedEthernetFrame.Data[6],
							FragmentOffset: binary.BigEndian.Uint16(recievedEthernetFrame.Data[6:8]),
							Ttl:            recievedEthernetFrame.Data[8],
							Protocol:       recievedEthernetFrame.Data[9],
							HeaderChecksum: binary.BigEndian.Uint16(recievedEthernetFrame.Data[10:12]),
							SrcAddr:        binary.BigEndian.Uint32(recievedEthernetFrame.Data[12:16]),
							DstAddr:        binary.BigEndian.Uint32(recievedEthernetFrame.Data[16:20]),
						}

						ipOfEth0, err := strIPToBytes(DEFAULT_IP_SOURCE)
						if err != nil {
							return err
						}
						switch ipv4.DstAddr {
						case binary.BigEndian.Uint32(ipOfEth0):
							viewersCh <- []viewer{recievedEthernetFrame, ipv4}
						}
					}
				}
			}
		}
	}

	return nil
}
