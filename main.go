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
	arp := newARP()
	dst := hardwareAddr(firsthopMACAddr)
	src := hardwareAddr(intf.HardwareAddr)
	ethernetFrame := newEthernetFrame(dst, src, ETHER_TYPE_ARP, arp.toBytes())
	return send(ethernetFrame, sock, addr)
}

func sendICMPechoRequest(sock int, addr unix.SockaddrLinklayer, intf net.Interface, firsthopMACAddr [6]byte) error {
	icmp := newICMP()
	ipv4 := newIPv4(IPv4_PROTO_ICMP)
	ipv4.data = icmp.toBytes()
	ipv4.calculateTotalLength()
	ipv4.calculateChecksum()
	dst := hardwareAddr(firsthopMACAddr)
	src := hardwareAddr(intf.HardwareAddr)
	ethernetFrame := newEthernetFrame(dst, src, ETHER_TYPE_IPv4, ipv4.toBytes())
	return send(ethernetFrame, sock, addr)
}

func sendDNSquery(sock int, addr unix.SockaddrLinklayer, intf net.Interface, firsthopMACAddr [6]byte) error {
	dns := &dns{
		transactionID: 0x1234,
		flags:         0x0100, // standard query
		questions:     0x0001,
		answerRRs:     0x0000,
		authorityRRs:  0x0000,
		additionalRRs: 0x0000,
		queries: &queries{
			typ:   0x0001, // A
			class: 0x0001, // IN
		},
	}
	// dns.domain("github.com")
	dns.domain("go.dev")
	udp := &udp{
		srcPort:  0x0401, // 1025
		dstPort:  0x0035, // 53
		length:   0x0000,
		checksum: 0x0000,
	}
	udp.data = dns.toBytes()
	udp.len()
	ipv4 := newIPv4(IPv4_PROTO_UDP)
	ipv4.data = udp.toBytes()
	ipv4.calculateTotalLength()
	ipv4.calculateChecksum()
	dst := hardwareAddr(firsthopMACAddr)
	src := hardwareAddr(intf.HardwareAddr)
	ethernetFrame := newEthernetFrame(dst, src, ETHER_TYPE_IPv4, ipv4.toBytes())
	return send(ethernetFrame, sock, addr)
}

func sendTCPsyn(sock int, addr unix.SockaddrLinklayer, intf net.Interface, firsthopMACAddr [6]byte) error {
	tcp := newTCPSyn()
	ipv4 := newIPv4(IPv4_PROTO_TCP)
	// https://atmarkit.itmedia.co.jp/ait/articles/0401/29/news080_2.html
	// 「「チェックサム」フィールド：16bit幅」
	tcp.checksum = func() uint16 {
		pseudoTCPHeader := func() []byte {
			var buf bytes.Buffer
			b := make([]byte, 4)
			binary.BigEndian.PutUint32(b, ipv4.srcAddr)
			buf.Write(b)
			b = make([]byte, 4)
			binary.BigEndian.PutUint32(b, ipv4.dstAddr)
			buf.Write(b)
			padding := byte(0x00)
			buf.WriteByte(padding)
			buf.WriteByte(ipv4.protocol)
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
	ipv4.data = tcp.toBytes()
	ipv4.calculateTotalLength()
	ipv4.calculateChecksum()
	dst := hardwareAddr(firsthopMACAddr)
	src := hardwareAddr(intf.HardwareAddr)
	ethernetFrame := newEthernetFrame(dst, src, ETHER_TYPE_IPv4, ipv4.toBytes())
	return send(ethernetFrame, sock, addr)
}

func sendHTTPget(sock int, addr unix.SockaddrLinklayer, intf net.Interface, firsthopMACAddr [6]byte) error {
	http := newHTTP()
	tcp := newTCPWithData(http.toBytes())
	ipv4 := newIPv4(IPv4_PROTO_TCP)
	// https://atmarkit.itmedia.co.jp/ait/articles/0401/29/news080_2.html
	// 「「チェックサム」フィールド：16bit幅」
	tcp.checksum = func() uint16 {
		pseudoTCPHeader := func() []byte {
			var buf bytes.Buffer
			b := make([]byte, 4)
			binary.BigEndian.PutUint32(b, ipv4.srcAddr)
			buf.Write(b)
			b = make([]byte, 4)
			binary.BigEndian.PutUint32(b, ipv4.dstAddr)
			buf.Write(b)
			padding := byte(0x00)
			buf.WriteByte(padding)
			buf.WriteByte(ipv4.protocol)
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
	ipv4.data = tcp.toBytes()
	ipv4.calculateTotalLength()
	ipv4.calculateChecksum()
	dst := hardwareAddr(firsthopMACAddr)
	src := hardwareAddr(intf.HardwareAddr)
	ethernetFrame := newEthernetFrame(dst, src, ETHER_TYPE_IPv4, ipv4.toBytes())
	return send(ethernetFrame, sock, addr)
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
			if events[i].Fd == int32(sock) {
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

						ipOfEth0, err := strIPToBytes(DEFAULT_IP_SOURCE)
						if err != nil {
							return err
						}
						switch ipv4.dstAddr {
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
