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
)

// 長さとか他のフィールドに基づいて計算しないといけない値があるから、そこは固定値ではなくてリアルタイムに反映したい
// とすると、高レイヤーの入力から埋めて進めていくようにしないといけなさそう. ユーザーが選べるようにするのがいいかも
func (t *tui) form(sendFn func(*packemon.EthernetFrame) error) error {
	ethernetHeader, arp, ipv4, icmp, err := defaultPackets()
	if err != nil {
		return err
	}

	icmpForm := t.icmpForm(sendFn, ethernetHeader, ipv4, icmp)
	icmpForm.SetBorder(true).SetTitle(" ICMP ").SetTitleAlign(tview.AlignLeft)
	ipv4Form := t.ipv4Form(sendFn, ethernetHeader, ipv4)
	ipv4Form.SetBorder(true).SetTitle(" IPv4 Header ").SetTitleAlign(tview.AlignLeft)
	arpForm := t.arpForm(sendFn, ethernetHeader, arp)
	arpForm.SetBorder(true).SetTitle(" ARP ").SetTitleAlign(tview.AlignLeft)
	ethernetForm := t.ethernetForm(sendFn, ethernetHeader)
	ethernetForm.SetBorder(true).SetTitle(" Ethernet Header ").SetTitleAlign(tview.AlignLeft)

	t.pages.
		AddPage("ICMP", icmpForm, true, true).
		AddPage("ARP", arpForm, true, true).
		AddPage("IPv4", ipv4Form, true, true).
		AddPage("Ethernet", ethernetForm, true, true)

	t.list.
		AddItem("ICMP", "", '1', func() {
			t.pages.SwitchToPage("ICMP")
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
		AddItem("Ethernet", "", '4', func() {
			t.pages.SwitchToPage("Ethernet")
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

func defaultPackets() (*packemon.EthernetHeader, *packemon.ARP, *packemon.IPv4, *packemon.ICMP, error) {
	icmpType, err := strHexToUint8(DEFAULT_ICMP_TYPE)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	icmpCode, err := strHexToUint8(DEFAULT_ICMP_CODE)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	icmpIdentifier, err := strHexToBytes2(DEFAULT_ICMP_IDENTIFIER)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	icmpSequence, err := strHexToBytes2(DEFAULT_ICMP_SEQUENCE)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	icmp := &packemon.ICMP{
		Typ:        icmpType,
		Code:       icmpCode,
		Identifier: binary.BigEndian.Uint16(icmpIdentifier),
		Sequence:   binary.BigEndian.Uint16(icmpSequence),
	}

	ip, err := strIPToBytes(DEFAULT_IP_SOURCE)
	if err != nil {
		return nil, nil, nil, nil, err
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
		return nil, nil, nil, nil, err
	}
	protocolType, err := strHexToBytes2(DEFAULT_ARP_PROTOCOL_TYPE)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	hardwareSize, err := strHexToUint8(DEFAULT_ARP_HARDWARE_SIZE)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	protocolSize, err := strHexToUint8(DEFAULT_ARP_PROTOCOL_SIZE)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	operation, err := strHexToBytes2(DEFAULT_ARP_OPERATION)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	senderMac, err := strHexToBytes(DEFAULT_ARP_SENDER_MAC)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	senderIP, err := strIPToBytes(DEFAULT_ARP_SENDER_IP)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	targetMac, err := strHexToBytes(DEFAULT_ARP_TARGET_MAC)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	targetIP, err := strIPToBytes(DEFAULT_ARP_TARGET_IP)
	if err != nil {
		return nil, nil, nil, nil, err
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
		return nil, nil, nil, nil, err
	}
	ethernetHeader := &packemon.EthernetHeader{
		Dst: packemon.HardwareAddr(mac),
		Src: packemon.HardwareAddr(mac),
		Typ: packemon.ETHER_TYPE_IPv4,
	}

	return ethernetHeader, arp, ipv4, icmp, nil
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
