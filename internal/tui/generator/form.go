package generator

import (
	"context"
	"encoding/binary"
	"net"
	"strconv"

	"github.com/ddddddO/packemon"
	"github.com/ddddddO/packemon/internal/tui"
	"github.com/rivo/tview"
)

// TODO: この辺りLABELとrenameした方が分かりやすそう
const (
	DEFAULT_ETHER_TYPE = "IPv4"
)

var (
	DEFAULT_NW_INTERFACE = "eth0" // TODO: 良くない直す

	DEFAULT_MAC_DESTINATION = ""
	DEFAULT_MAC_SOURCE      = ""

	DEFAULT_ARP_HARDWARE_TYPE = "0x0001"
	DEFAULT_ARP_PROTOCOL_TYPE = "0x0800"
	DEFAULT_ARP_HARDWARE_SIZE = "0x06"
	DEFAULT_ARP_PROTOCOL_SIZE = "0x04"
	DEFAULT_ARP_OPERATION     = "0x0001"
	DEFAULT_ARP_SENDER_MAC    = ""
	DEFAULT_ARP_SENDER_IP     = ""
	DEFAULT_ARP_TARGET_MAC    = "0x000000000000"
	DEFAULT_ARP_TARGET_IP     = ""

	DEFAULT_IP_PROTOCOL    = "ICMP"
	DEFAULT_IP_SOURCE      = ""
	DEFAULT_IP_DESTINATION = ""

	DEFAULT_IPv6_PROTOCOL    = "ICMPv6"
	DEFAULT_IPv6_SOURCE      = ""
	DEFAULT_IPv6_DESTINATION = ""

	DEFAULT_ICMP_TYPE       = "0x08"
	DEFAULT_ICMP_CODE       = "0x00"
	DEFAULT_ICMP_IDENTIFIER = "0x34a1"
	DEFAULT_ICMP_SEQUENCE   = "0x0001"

	DEFAULT_UDP_PORT_SOURCE      = "47000"
	DEFAULT_UDP_PORT_DESTINATION = "53"
	DEFAULT_UDP_LENGTH           = "0x0030"

	DEFAULT_DNS_TRANSACTION    = "0xaa78"
	DEFAULT_DNS_FLAGS          = "0x0100"
	DEFAULT_DNS_QUESTIONS      = "0x0001"
	DEFAULT_DNS_ANSWERS_RRs    = "0x0000"
	DEFAULT_DNS_AUTHORITYR_Rs  = "0x0000"
	DEFAULT_DNS_ADDITIONAL_RRs = "0x0000"
	DEFAULT_DNS_QUERIES_DOMAIN = "go.dev"
	DEFAULT_DNS_QUERIES_TYPE   = "0x0001"
	DEFAULT_DNS_QUERIES_CLASS  = "0x0001"

	DEFAULT_TCP_PORT_SOURCE      = "47000"
	DEFAULT_TCP_PORT_DESTINATION = "80"
	DEFAULT_TCP_SEQUENCE         = "0x1f6e9499"
	DEFAULT_TCP_FLAGS            = "0x02"

	DEFAULT_HTTP_METHOD     = "GET"
	DEFAULT_HTTP_URI        = "/"
	DEFAULT_HTTP_VERSION    = "HTTP/1.1"
	DEFAULT_HTTP_HOST       = "github.com"
	DEFAULT_HTTP_USER_AGENT = "packemon"
	DEFAULT_HTTP_ACCEPT     = "*/*"
)

// 長さとか他のフィールドに基づいて計算しないといけない値があるから、そこは固定値ではなくてリアルタイムに反映したい
// とすると、高レイヤーの入力から埋めて進めていくようにしないといけなさそう. ユーザーが選べるようにするのがいいかも
func (g *generator) form(ctx context.Context, sendFn func(*packemon.EthernetFrame) error) error {
	packets, err := defaultPackets()
	if err != nil {
		return err
	}
	g.sender = newSender(packets, sendFn)

	// L7
	httpForm := g.httpForm(ctx)
	httpForm.SetBorder(true).SetTitle(" HTTP ").SetTitleAlign(tview.AlignLeft)
	dnsForm := g.dnsForm()
	dnsForm.SetBorder(true).SetTitle(" DNS ").SetTitleAlign(tview.AlignLeft)

	// L5~L6
	tlsv1_2Form := g.tlsv1_2Form()
	tlsv1_2Form.SetBorder(true).SetTitle(" TLSv1.2 ").SetTitleAlign(tview.AlignLeft)
	tlsv1_3Form := g.tlsv1_3Form()
	tlsv1_3Form.SetBorder(true).SetTitle(" TLSv1.3 ").SetTitleAlign(tview.AlignLeft)

	// L4
	tcpForm := g.tcpForm()
	tcpForm.SetBorder(true).SetTitle(" TCP ").SetTitleAlign(tview.AlignLeft)
	udpForm := g.udpForm()
	udpForm.SetBorder(true).SetTitle(" UDP ").SetTitleAlign(tview.AlignLeft)
	icmpForm := g.icmpForm()
	icmpForm.SetBorder(true).SetTitle(" ICMP ").SetTitleAlign(tview.AlignLeft)

	// L3
	ipv6Form := g.ipv6Form()
	ipv6Form.SetBorder(true).SetTitle(" IPv6 Header ").SetTitleAlign(tview.AlignLeft)
	ipv4Form := g.ipv4Form()
	ipv4Form.SetBorder(true).SetTitle(" IPv4 Header ").SetTitleAlign(tview.AlignLeft)
	arpForm := g.arpForm()
	arpForm.SetBorder(true).SetTitle(" ARP ").SetTitleAlign(tview.AlignLeft)

	// L2
	ethernetForm := g.ethernetForm()
	ethernetForm.SetBorder(true).SetTitle(" Ethernet Header ").SetTitleAlign(tview.AlignLeft)

	g.pages.
		AddPage("HTTP", httpForm, true, true).
		AddPage("DNS", dnsForm, true, true).
		AddPage("TLSv1.2", tlsv1_2Form, true, true).
		AddPage("TLSv1.3", tlsv1_3Form, true, true).
		AddPage("UDP", udpForm, true, true).
		AddPage("TCP", tcpForm, true, true).
		AddPage("ICMP", icmpForm, true, true).
		AddPage("IPv6", ipv6Form, true, true).
		AddPage("IPv4", ipv4Form, true, true).
		AddPage("ARP", arpForm, true, true).
		AddPage("Ethernet", ethernetForm, true, true)

	switchProtocol := func(targetLayer string) func(targetProtocol string, switchableProtocols []string) {
		return func(targetProtocol string, switchableProtocols []string) {
			for _, protocol := range switchableProtocols {
				if targetProtocol == protocol {
					g.sender.selectedProtocolByLayer[targetLayer] = targetProtocol
					g.pages.SwitchToPage(targetProtocol)
					g.app.SetFocus(g.pages)
				}
			}
		}
	}

	// TODO: というよりはメモ
	//       QUIC が UDP より上位でアプリケーションレイヤより下位でしかも、TLS を内部で使って暗号化するみたいで、そうするとL5/6の内に入りそうだけど、TLS と同居はできない（今の Generator 実装上）
	//       L5 と L6 でそれぞれ分けていいかもだけど、OSI参照モデルのセッション層・プレゼンテーション層と合わないだろうし、
	//       L + ギリシャ文字 でレイヤを表すようにする。ref: ギリシャ文字: https://opencourse.doshisha.ac.jp/opc/bj01/math-intro/PC/greece.html

	l7s := []string{"", "DNS", "HTTP"}
	l7Protocols := tview.NewDropDown()
	l7Protocols.SetTitle("Lε").SetBorder(true)
	l7Protocols.SetOptions(l7s, func(text string, index int) {
		switchProtocol("L7")(text, l7s)
	})
	l7Protocols.SetCurrentOption(1)

	l5_6s := []string{"", "TLSv1.2", "TLSv1.3"}
	l5_6Protocols := tview.NewDropDown()
	l5_6Protocols.SetTitle("Lδ").SetBorder(true)
	l5_6Protocols.SetOptions(l5_6s, func(text string, index int) {
		switchProtocol("L5/6")(text, l5_6s)
	})
	l5_6Protocols.SetCurrentOption(0)

	l4s := []string{"", "ICMP", "TCP", "UDP"}
	l4Protocols := tview.NewDropDown()
	l4Protocols.SetTitle("Lγ").SetBorder(true)
	l4Protocols.SetOptions(l4s, func(text string, index int) {
		switchProtocol("L4")(text, l4s)
	})
	l4Protocols.SetCurrentOption(3)

	l3s := []string{"", "ARP", "IPv4", "IPv6"}
	l3Protocols := tview.NewDropDown()
	l3Protocols.SetTitle("Lβ").SetBorder(true)
	l3Protocols.SetOptions(l3s, func(text string, index int) {
		switchProtocol("L3")(text, l3s)
	})
	l3Protocols.SetCurrentOption(2)

	l2s := []string{"Ethernet"}
	l2Protocols := tview.NewDropDown()
	l2Protocols.SetTitle("Lα").SetBorder(true)
	l2Protocols.SetOptions(l2s, func(text string, index int) {
		switchProtocol("L2")(text, l2s)
	})
	l2Protocols.SetCurrentOption(0)

	// Interface の情報を出力するための
	interfaceTable := tview.NewTable().SetBorders(true)
	{
		intf, err := net.InterfaceByName(g.networkInterface.Intf.Name)
		if err != nil {
			return err
		}
		addrs, err := intf.Addrs()
		if err != nil {
			return err
		}

		interfaceTable.Box = tview.NewBox().SetBorder(true).SetTitle(" Interface ")
		interfaceTable.SetCell(0, 0, tui.TableCellTitle("name"))
		interfaceTable.SetCell(0, 1, tui.TableCellContent("%s", g.networkInterface.Intf.Name))
		interfaceTable.SetCell(1, 0, tui.TableCellTitle("mac address"))
		interfaceTable.SetCell(1, 1, tui.TableCellContent("%s", g.networkInterface.Intf.HardwareAddr.String()))
		interfaceTable.SetCell(2, 0, tui.TableCellTitle("ip address"))
		for i, addr := range addrs {
			interfaceTable.SetCell(2+i, 1, tui.TableCellContent("%s", addr))
		}
	}

	layerRowNum := 3
	g.grid.
		SetRows(layerRowNum, layerRowNum, layerRowNum, layerRowNum, layerRowNum, -2, -2).
		SetColumns(-1, -5)

	g.grid.
		// 左側
		AddItem(l2Protocols, 0, 0, 1, 1, layerRowNum, 0, true).
		AddItem(l3Protocols, 1, 0, 1, 1, layerRowNum, 0, false).
		AddItem(l4Protocols, 2, 0, 1, 1, layerRowNum, 0, false).
		AddItem(l5_6Protocols, 3, 0, 1, 1, layerRowNum, 0, false).
		AddItem(l7Protocols, 4, 0, 1, 1, layerRowNum, 0, false).

		// 右側
		AddItem(g.pages, 0, 1, 8, 1, 0, 0, false).
		AddItem(interfaceTable, 8, 1, 2, 1, 0, 0, false)

	return nil
}

type packets struct {
	ethernet *packemon.EthernetHeader
	arp      *packemon.ARP
	ipv4     *packemon.IPv4
	ipv6     *packemon.IPv6
	icmpv4   *packemon.ICMP
	tcp      *packemon.TCP
	udp      *packemon.UDP
	dns      *packemon.DNS
	http     *packemon.HTTP
}

func defaultPackets() (*packets, error) {
	http := &packemon.HTTP{
		Method:    DEFAULT_HTTP_METHOD,
		Uri:       DEFAULT_HTTP_URI,
		Version:   DEFAULT_HTTP_VERSION,
		Host:      DEFAULT_HTTP_HOST,
		UserAgent: DEFAULT_HTTP_USER_AGENT,
		Accept:    DEFAULT_HTTP_ACCEPT,
	}

	dns := &packemon.DNS{}
	dnsTransactionID, err := packemon.StrHexToBytes2(DEFAULT_DNS_TRANSACTION)
	if err != nil {
		return nil, err
	}
	dns.TransactionID = binary.BigEndian.Uint16(dnsTransactionID)
	dnsFlags, err := packemon.StrHexToBytes2(DEFAULT_DNS_FLAGS)
	if err != nil {
		return nil, err
	}
	dns.Flags = binary.BigEndian.Uint16(dnsFlags)
	dnsQuestions, err := packemon.StrHexToBytes2(DEFAULT_DNS_QUESTIONS)
	if err != nil {
		return nil, err
	}
	dns.Questions = binary.BigEndian.Uint16(dnsQuestions)
	dnsAnswerRRs, err := packemon.StrHexToBytes2(DEFAULT_DNS_ANSWERS_RRs)
	if err != nil {
		return nil, err
	}
	dns.AnswerRRs = binary.BigEndian.Uint16(dnsAnswerRRs)
	dnsAuthorityRRs, err := packemon.StrHexToBytes2(DEFAULT_DNS_AUTHORITYR_Rs)
	if err != nil {
		return nil, err
	}
	dns.AuthorityRRs = binary.BigEndian.Uint16(dnsAuthorityRRs)
	dnsAdditionalRRs, err := packemon.StrHexToBytes2(DEFAULT_DNS_ADDITIONAL_RRs)
	if err != nil {
		return nil, err
	}
	dns.AdditionalRRs = binary.BigEndian.Uint16(dnsAdditionalRRs)
	dnsQueriesType, err := packemon.StrHexToBytes2(DEFAULT_DNS_QUERIES_TYPE)
	if err != nil {
		return nil, err
	}
	dnsQueriesClass, err := packemon.StrHexToBytes2(DEFAULT_DNS_QUERIES_CLASS)
	if err != nil {
		return nil, err
	}
	queries := &packemon.Queries{
		Typ:   binary.BigEndian.Uint16(dnsQueriesType),
		Class: binary.BigEndian.Uint16(dnsQueriesClass),
	}
	dns.Queries = queries
	dns.Domain("go.dev")

	udpSrcPort, err := packemon.StrIntToUint16(DEFAULT_UDP_PORT_SOURCE)
	if err != nil {
		return nil, err
	}
	udpDstPort, err := packemon.StrIntToUint16(DEFAULT_UDP_PORT_DESTINATION)
	if err != nil {
		return nil, err
	}
	udpLength, err := packemon.StrHexToBytes2(DEFAULT_UDP_LENGTH)
	if err != nil {
		return nil, err
	}
	udp := &packemon.UDP{
		SrcPort:  udpSrcPort,
		DstPort:  udpDstPort,
		Checksum: 0x0000,
		Length:   binary.BigEndian.Uint16(udpLength),
	}

	tcp := &packemon.TCP{
		Acknowledgment: 0x00000000,
		// HeaderLength:   0x00a0,
		HeaderLength:  0x0050, // 0101
		Window:        0xfaf0,
		Checksum:      0x0000,
		UrgentPointer: 0x0000,
		// Options:        packemon.Options(),
	}
	tcpSrcPort, err := packemon.StrIntToUint16(DEFAULT_TCP_PORT_SOURCE)
	if err != nil {
		return nil, err
	}
	tcp.SrcPort = tcpSrcPort
	tcpDstPort, err := packemon.StrIntToUint16(DEFAULT_TCP_PORT_DESTINATION)
	if err != nil {
		return nil, err
	}
	tcp.DstPort = tcpDstPort
	tcpSequence, err := strHexToBytes3(DEFAULT_TCP_SEQUENCE)
	if err != nil {
		return nil, err
	}
	tcp.Sequence = binary.BigEndian.Uint32(tcpSequence)
	tcpFlags, err := packemon.StrHexToBytes3(DEFAULT_TCP_FLAGS)
	if err != nil {
		return nil, err
	}
	tcp.Flags = tcpFlags

	icmpType, err := strHexToUint8(DEFAULT_ICMP_TYPE)
	if err != nil {
		return nil, err
	}
	icmpCode, err := strHexToUint8(DEFAULT_ICMP_CODE)
	if err != nil {
		return nil, err
	}
	icmpIdentifier, err := packemon.StrHexToBytes2(DEFAULT_ICMP_IDENTIFIER)
	if err != nil {
		return nil, err
	}
	icmpSequence, err := packemon.StrHexToBytes2(DEFAULT_ICMP_SEQUENCE)
	if err != nil {
		return nil, err
	}
	icmp := &packemon.ICMP{
		Typ:        icmpType,
		Code:       icmpCode,
		Identifier: binary.BigEndian.Uint16(icmpIdentifier),
		Sequence:   binary.BigEndian.Uint16(icmpSequence),
	}

	srcIP, err := packemon.StrIPToBytes(DEFAULT_IP_SOURCE)
	if err != nil {
		return nil, err
	}
	dstIP, err := packemon.StrIPToBytes(DEFAULT_IP_DESTINATION)
	if err != nil {
		return nil, err
	}

	ipv4 := &packemon.IPv4{
		Version:        0x04,
		Ihl:            0x05,
		Tos:            0x00,
		TotalLength:    0x14,
		Identification: 0xe31f,
		Flags:          0x40,
		FragmentOffset: 0x0,
		Ttl:            0x80,
		Protocol:       packemon.IPv4_PROTO_UDP,
		HeaderChecksum: 0,
		SrcAddr:        binary.BigEndian.Uint32(srcIP),
		DstAddr:        binary.BigEndian.Uint32(dstIP),
	}

	srcIPv6 := net.ParseIP(DEFAULT_IPv6_SOURCE)
	if srcIPv6 == nil {
		return nil, err
	}
	dstIPv6 := net.ParseIP(DEFAULT_IPv6_DESTINATION)
	if dstIPv6 == nil {
		return nil, err
	}

	ipv6 := &packemon.IPv6{
		Version:      0x06,
		TrafficClass: 0x00,
		// FlowLabel:     0x7d77b,
		FlowLabel:     0x00000,
		PayloadLength: 0x0000,
		NextHeader:    packemon.IPv6_NEXT_HEADER_ICMPv6,
		HopLimit:      0x40,
		SrcAddr:       srcIPv6.To16(),
		DstAddr:       dstIPv6.To16(),
	}

	hardwareType, err := packemon.StrHexToBytes2(DEFAULT_ARP_HARDWARE_TYPE)
	if err != nil {
		return nil, err
	}
	protocolType, err := packemon.StrHexToBytes2(DEFAULT_ARP_PROTOCOL_TYPE)
	if err != nil {
		return nil, err
	}
	hardwareSize, err := strHexToUint8(DEFAULT_ARP_HARDWARE_SIZE)
	if err != nil {
		return nil, err
	}
	protocolSize, err := strHexToUint8(DEFAULT_ARP_PROTOCOL_SIZE)
	if err != nil {
		return nil, err
	}
	operation, err := packemon.StrHexToBytes2(DEFAULT_ARP_OPERATION)
	if err != nil {
		return nil, err
	}
	senderMac, err := packemon.StrHexToBytes(DEFAULT_ARP_SENDER_MAC)
	if err != nil {
		return nil, err
	}
	senderIP, err := packemon.StrIPToBytes(DEFAULT_ARP_SENDER_IP)
	if err != nil {
		return nil, err
	}
	targetMac, err := packemon.StrHexToBytes(DEFAULT_ARP_TARGET_MAC)
	if err != nil {
		return nil, err
	}
	targetIP, err := packemon.StrIPToBytes(DEFAULT_ARP_TARGET_IP)
	if err != nil {
		return nil, err
	}

	arp := &packemon.ARP{
		HardwareType:       binary.BigEndian.Uint16(hardwareType),
		ProtocolType:       binary.BigEndian.Uint16(protocolType),
		HardwareAddrLength: hardwareSize,
		ProtocolLength:     protocolSize,
		Operation:          binary.BigEndian.Uint16(operation),

		SenderHardwareAddr: [6]byte(senderMac),
		SenderIPAddr:       binary.BigEndian.Uint32(senderIP),

		TargetHardwareAddr: [6]byte(targetMac),
		TargetIPAddr:       binary.BigEndian.Uint32(targetIP),
	}

	dstMAC, err := packemon.StrHexToBytes(DEFAULT_MAC_DESTINATION)
	if err != nil {
		return nil, err
	}
	srcMAC, err := packemon.StrHexToBytes(DEFAULT_MAC_SOURCE)
	if err != nil {
		return nil, err
	}
	ethernetHeader := &packemon.EthernetHeader{
		Dst: packemon.HardwareAddr(dstMAC),
		Src: packemon.HardwareAddr(srcMAC),
		Typ: packemon.ETHER_TYPE_IPv4,
	}

	return &packets{
		ethernet: ethernetHeader,
		arp:      arp,
		ipv4:     ipv4,
		ipv6:     ipv6,
		icmpv4:   icmp,
		udp:      udp,
		tcp:      tcp,
		dns:      dns,
		http:     http,
	}, nil
}

// TODO: rename or refactor
func strHexToBytes3(s string) ([]byte, error) {
	n, err := strconv.ParseUint(s, 0, 32)
	if err != nil {
		return nil, err
	}

	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, uint32(n))
	return buf, nil
}

func strHexToUint8(s string) (uint8, error) {
	n, err := strconv.ParseUint(s, 0, 8)
	if err != nil {
		return 0, err
	}
	return uint8(n), nil
}
