package tui

import (
	"encoding/binary"
	"strconv"
	"strings"

	"github.com/ddddddO/packemon"
	"github.com/rivo/tview"
)

// TODO: この辺りLABELとrenameした方が分かりやすそう
const (
	DEFAULT_ETHER_TYPE = "IPv4"
)

var (
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

	DEFAULT_ICMP_TYPE       = "0x08"
	DEFAULT_ICMP_CODE       = "0x00"
	DEFAULT_ICMP_IDENTIFIER = "0x34a1"
	DEFAULT_ICMP_SEQUENCE   = "0x0001"

	DEFAULT_UDP_PORT_SOURCE      = "12345"
	DEFAULT_UDP_PORT_DESTINATION = "53"
	DEFAULT_UDP_LENGTH           = "0x0030"

	DEFAULT_DNS_TRANSACTION    = "0x1234"
	DEFAULT_DNS_FLAGS          = "0x0100"
	DEFAULT_DNS_QUESTIONS      = "0x0001"
	DEFAULT_DNS_ANSWERS_RRs    = "0x0000"
	DEFAULT_DNS_AUTHORITYR_Rs  = "0x0000"
	DEFAULT_DNS_ADDITIONAL_RRs = "0x0000"
	DEFAULT_DNS_QUERIES_DOMAIN = "go.dev"
	DEFAULT_DNS_QUERIES_TYPE   = "0x0001"
	DEFAULT_DNS_QUERIES_CLASS  = "0x0001"

	DEFAULT_TCP_PORT_SOURCE      = "12345"
	DEFAULT_TCP_PORT_DESTINATION = "80"
	DEFAULT_TCP_SEQUENCE         = "0x1f6e9499"
	DEFAULT_TCP_FLAGS            = "0x002"
)

// 長さとか他のフィールドに基づいて計算しないといけない値があるから、そこは固定値ではなくてリアルタイムに反映したい
// とすると、高レイヤーの入力から埋めて進めていくようにしないといけなさそう. ユーザーが選べるようにするのがいいかも
func (t *tui) form(sendFn func(*packemon.EthernetFrame) error) error {
	d, err := defaultPackets()
	if err != nil {
		return err
	}
	ethernetHeader, arp, ipv4, icmp, udp, tcp, dns := d.e, d.a, d.ip, d.ic, d.u, d.t, d.d

	dnsForm := t.dnsForm(sendFn, ethernetHeader, ipv4, udp, dns)
	dnsForm.SetBorder(true).SetTitle(" DNS ").SetTitleAlign(tview.AlignLeft)
	tcpForm := t.tcpForm(sendFn, ethernetHeader, ipv4, tcp)
	tcpForm.SetBorder(true).SetTitle(" TCP ").SetTitleAlign(tview.AlignLeft)
	udpForm := t.udpForm(sendFn, ethernetHeader, ipv4, udp)
	udpForm.SetBorder(true).SetTitle(" UDP ").SetTitleAlign(tview.AlignLeft)
	icmpForm := t.icmpForm(sendFn, ethernetHeader, ipv4, icmp)
	icmpForm.SetBorder(true).SetTitle(" ICMP ").SetTitleAlign(tview.AlignLeft)
	ipv4Form := t.ipv4Form(sendFn, ethernetHeader, ipv4)
	ipv4Form.SetBorder(true).SetTitle(" IPv4 Header ").SetTitleAlign(tview.AlignLeft)
	arpForm := t.arpForm(sendFn, ethernetHeader, arp)
	arpForm.SetBorder(true).SetTitle(" ARP ").SetTitleAlign(tview.AlignLeft)
	ethernetForm := t.ethernetForm(sendFn, ethernetHeader)
	ethernetForm.SetBorder(true).SetTitle(" Ethernet Header ").SetTitleAlign(tview.AlignLeft)

	t.pages.
		AddPage("DNS", dnsForm, true, true).
		AddPage("UDP", udpForm, true, true).
		AddPage("TCP", tcpForm, true, true).
		AddPage("ICMP", icmpForm, true, true).
		AddPage("ARP", arpForm, true, true).
		AddPage("IPv4", ipv4Form, true, true).
		AddPage("Ethernet", ethernetForm, true, true)

	t.list.
		AddItem("Ethernet", "", '1', func() {
			t.pages.SwitchToPage("Ethernet")
			t.app.SetFocus(t.pages)
		}).
		AddItem("IPv4", "", '2', func() {
			t.pages.SwitchToPage("IPv4")
			t.app.SetFocus(t.pages)
		}).
		AddItem("ARP", "", '3', func() {
			t.pages.SwitchToPage("ARP")
			t.app.SetFocus(t.pages)
		}).
		AddItem("ICMP", "", '4', func() {
			t.pages.SwitchToPage("ICMP")
			t.app.SetFocus(t.pages)
		}).
		AddItem("TCP", "", '5', func() {
			t.pages.SwitchToPage("TCP")
			t.app.SetFocus(t.pages)
		}).
		AddItem("UDP", "", '6', func() {
			t.pages.SwitchToPage("UDP")
			t.app.SetFocus(t.pages)
		}).
		AddItem("DNS", "", '7', func() {
			t.pages.SwitchToPage("DNS")
			t.app.SetFocus(t.pages)
		})

	t.grid.
		SetRows(1, 0).
		SetColumns(30, 0)
	// TODO: 見切れちゃう
	// Layout for screens narrower than 100 cells (menu and side bar are hidden).
	t.grid.AddItem(t.list, 1, 0, 1, 1, 0, 0, true).
		AddItem(t.pages, 1, 1, 1, 1, 0, 0, false)

	// Layout for screens wider than 100 cells.
	t.grid.AddItem(t.list, 1, 0, 1, 1, 0, 100, true).
		AddItem(t.pages, 1, 1, 1, 1, 0, 100, false)

	return nil
}

type defaults struct {
	e  *packemon.EthernetHeader
	a  *packemon.ARP
	ip *packemon.IPv4
	ic *packemon.ICMP
	t  *packemon.TCP
	u  *packemon.UDP
	d  *packemon.DNS
}

func defaultPackets() (*defaults, error) {
	dns := &packemon.DNS{}
	dnsTransactionID, err := strHexToBytes2(DEFAULT_DNS_TRANSACTION)
	if err != nil {
		return nil, err
	}
	dns.TransactionID = binary.BigEndian.Uint16(dnsTransactionID)
	dnsFlags, err := strHexToBytes2(DEFAULT_DNS_FLAGS)
	if err != nil {
		return nil, err
	}
	dns.Flags = binary.BigEndian.Uint16(dnsFlags)
	dnsQuestions, err := strHexToBytes2(DEFAULT_DNS_QUESTIONS)
	if err != nil {
		return nil, err
	}
	dns.Questions = binary.BigEndian.Uint16(dnsQuestions)
	dnsAnswerRRs, err := strHexToBytes2(DEFAULT_DNS_ANSWERS_RRs)
	if err != nil {
		return nil, err
	}
	dns.AnswerRRs = binary.BigEndian.Uint16(dnsAnswerRRs)
	dnsAuthorityRRs, err := strHexToBytes2(DEFAULT_DNS_AUTHORITYR_Rs)
	if err != nil {
		return nil, err
	}
	dns.AuthorityRRs = binary.BigEndian.Uint16(dnsAuthorityRRs)
	dnsAdditionalRRs, err := strHexToBytes2(DEFAULT_DNS_ADDITIONAL_RRs)
	if err != nil {
		return nil, err
	}
	dns.AdditionalRRs = binary.BigEndian.Uint16(dnsAdditionalRRs)
	dnsQueriesType, err := strHexToBytes2(DEFAULT_DNS_QUERIES_TYPE)
	if err != nil {
		return nil, err
	}
	dnsQueriesClass, err := strHexToBytes2(DEFAULT_DNS_QUERIES_CLASS)
	if err != nil {
		return nil, err
	}
	queries := &packemon.Queries{
		Typ:   binary.BigEndian.Uint16(dnsQueriesType),
		Class: binary.BigEndian.Uint16(dnsQueriesClass),
	}
	dns.Queries = queries
	dns.Domain("go.dev")

	udpSrcPort, err := strIntToUint16(DEFAULT_UDP_PORT_SOURCE)
	if err != nil {
		return nil, err
	}
	udpDstPort, err := strIntToUint16(DEFAULT_UDP_PORT_DESTINATION)
	if err != nil {
		return nil, err
	}
	udpLength, err := strHexToBytes2(DEFAULT_UDP_LENGTH)
	if err != nil {
		return nil, err
	}
	udp := &packemon.UDP{
		SrcPort: udpSrcPort,
		DstPort: udpDstPort,
		Length:  binary.BigEndian.Uint16(udpLength),
	}
	udp.Len()

	tcp := &packemon.TCP{
		Acknowledgment: 0x00000000,
		HeaderLength:   0x00a0,
		Window:         0xfaf0,
		Checksum:       0x0000,
		UrgentPointer:  0x0000,
		Options:        packemon.Options(),
	}
	tcpSrcPort, err := strIntToUint16(DEFAULT_TCP_PORT_SOURCE)
	if err != nil {
		return nil, err
	}
	tcp.SrcPort = tcpSrcPort
	tcpDstPort, err := strIntToUint16(DEFAULT_TCP_PORT_DESTINATION)
	if err != nil {
		return nil, err
	}
	tcp.DstPort = tcpDstPort
	tcpSequence, err := strHexToBytes3(DEFAULT_TCP_SEQUENCE)
	if err != nil {
		return nil, err
	}
	tcp.Sequence = binary.BigEndian.Uint32(tcpSequence)
	tcpFlags, err := strHexToBytes2(DEFAULT_TCP_FLAGS)
	if err != nil {
		return nil, err
	}
	tcp.Flags = binary.BigEndian.Uint16(tcpFlags)

	icmpType, err := strHexToUint8(DEFAULT_ICMP_TYPE)
	if err != nil {
		return nil, err
	}
	icmpCode, err := strHexToUint8(DEFAULT_ICMP_CODE)
	if err != nil {
		return nil, err
	}
	icmpIdentifier, err := strHexToBytes2(DEFAULT_ICMP_IDENTIFIER)
	if err != nil {
		return nil, err
	}
	icmpSequence, err := strHexToBytes2(DEFAULT_ICMP_SEQUENCE)
	if err != nil {
		return nil, err
	}
	icmp := &packemon.ICMP{
		Typ:        icmpType,
		Code:       icmpCode,
		Identifier: binary.BigEndian.Uint16(icmpIdentifier),
		Sequence:   binary.BigEndian.Uint16(icmpSequence),
	}

	ip, err := strIPToBytes(DEFAULT_IP_SOURCE)
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
		Protocol:       packemon.IPv4_PROTO_ICMP,
		HeaderChecksum: 0,
		SrcAddr:        binary.BigEndian.Uint32(ip),
		DstAddr:        binary.BigEndian.Uint32(ip),
	}

	hardwareType, err := strHexToBytes2(DEFAULT_ARP_HARDWARE_TYPE)
	if err != nil {
		return nil, err
	}
	protocolType, err := strHexToBytes2(DEFAULT_ARP_PROTOCOL_TYPE)
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
	operation, err := strHexToBytes2(DEFAULT_ARP_OPERATION)
	if err != nil {
		return nil, err
	}
	senderMac, err := strHexToBytes(DEFAULT_ARP_SENDER_MAC)
	if err != nil {
		return nil, err
	}
	senderIP, err := strIPToBytes(DEFAULT_ARP_SENDER_IP)
	if err != nil {
		return nil, err
	}
	targetMac, err := strHexToBytes(DEFAULT_ARP_TARGET_MAC)
	if err != nil {
		return nil, err
	}
	targetIP, err := strIPToBytes(DEFAULT_ARP_TARGET_IP)
	if err != nil {
		return nil, err
	}

	arp := &packemon.ARP{
		HardwareType:       [2]byte(hardwareType),
		ProtocolType:       binary.BigEndian.Uint16(protocolType),
		HardwareAddrLength: hardwareSize,
		ProtocolLength:     protocolSize,
		Operation:          [2]byte(operation),

		SenderHardwareAddr: [6]byte(senderMac),
		SenderIPAddr:       [4]byte(senderIP),

		TargetHardwareAddr: [6]byte(targetMac),
		TargetIPAddr:       [4]byte(targetIP),
	}

	mac, err := strHexToBytes(DEFAULT_MAC_SOURCE)
	if err != nil {
		return nil, err
	}
	ethernetHeader := &packemon.EthernetHeader{
		Dst: packemon.HardwareAddr(mac),
		Src: packemon.HardwareAddr(mac),
		Typ: packemon.ETHER_TYPE_IPv4,
	}

	return &defaults{
		e:  ethernetHeader,
		a:  arp,
		ip: ipv4,
		ic: icmp,
		u:  udp,
		t:  tcp,
		d:  dns,
	}, nil
}

// TODO: rename or refactor
func strHexToBytes(s string) ([]byte, error) {
	n, err := strconv.ParseUint(s, 0, 48)
	if err != nil {
		return nil, err
	}

	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, n)
	return buf[2:], nil
}

// TODO: rename or refactor
func strHexToBytes2(s string) ([]byte, error) {
	n, err := strconv.ParseUint(s, 0, 16)
	if err != nil {
		return nil, err
	}

	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, uint16(n))
	return buf, nil
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

func strIntToUint16(s string) (uint16, error) {
	n, err := strconv.ParseUint(s, 0, 16)
	if err != nil {
		return 0, err
	}
	return uint16(n), nil
}

func strHexToUint8(s string) (uint8, error) {
	n, err := strconv.ParseUint(s, 0, 8)
	if err != nil {
		return 0, err
	}
	return uint8(n), nil
}

func strIPToBytes(s string) ([]byte, error) {
	b := make([]byte, 4)
	src := strings.Split(s, ".")

	for i := range src {
		if len(src[i]) == 0 {
			continue
		}
		ip, err := strconv.ParseUint(src[i], 10, 8)
		if err != nil {
			return nil, err
		}
		b[i] = byte(ip)
	}
	return b, nil
}
