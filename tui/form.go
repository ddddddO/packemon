package tui

import (
	"encoding/binary"
	"strconv"
	"strings"
	"time"

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

	ip, err := StrIPToBytes(DEFAULT_IP_SOURCE)
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
	senderIP, err := StrIPToBytes(DEFAULT_ARP_SENDER_IP)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	targetMac, err := strHexToBytes(DEFAULT_ARP_TARGET_MAC)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	targetIP, err := StrIPToBytes(DEFAULT_ARP_TARGET_IP)
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

func StrIPToBytes(s string) ([]byte, error) {
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

func (t *tui) icmpForm(sendFn func(*packemon.EthernetFrame) error, ethernetHeader *packemon.EthernetHeader, ipv4 *packemon.IPv4, icmp *packemon.ICMP) *tview.Form {
	icmpForm := tview.NewForm().
		AddTextView("ICMP", "This section generates the ICMP.\nIt is still under development.", 60, 4, true, false).
		AddInputField("Type(hex)", DEFAULT_ICMP_TYPE, 4, func(textToCheck string, lastChar rune) bool {
			if len(textToCheck) < 4 {
				return true
			} else if len(textToCheck) > 4 {
				return false
			}

			b, err := strHexToUint8(textToCheck)
			if err != nil {
				return false
			}
			icmp.Typ = uint8(b)

			return true
		}, nil).
		AddInputField("Code(hex)", DEFAULT_ICMP_CODE, 4, func(textToCheck string, lastChar rune) bool {
			if len(textToCheck) < 4 {
				return true
			} else if len(textToCheck) > 4 {
				return false
			}

			b, err := strHexToUint8(textToCheck)
			if err != nil {
				return false
			}
			icmp.Code = uint8(b)

			return true
		}, nil).
		AddInputField("Identifier(hex)", DEFAULT_ICMP_IDENTIFIER, 6, func(textToCheck string, lastChar rune) bool {
			if len(textToCheck) < 6 {
				return true
			} else if len(textToCheck) > 6 {
				return false
			}

			b, err := strHexToBytes2(textToCheck)
			if err != nil {
				return false
			}
			icmp.Identifier = binary.BigEndian.Uint16(b)

			return true
		}, nil).
		AddInputField("Sequence(hex)", DEFAULT_ICMP_SEQUENCE, 6, func(textToCheck string, lastChar rune) bool {
			if len(textToCheck) < 6 {
				return true
			} else if len(textToCheck) > 6 {
				return false
			}

			b, err := strHexToBytes2(textToCheck)
			if err != nil {
				return false
			}
			icmp.Sequence = binary.BigEndian.Uint16(b)

			return true
		}, nil).
		AddButton("Send!", func() {
			// TODO: timestamp関数化
			icmp.Data = func() []byte {
				now := time.Now().Unix()
				b := make([]byte, 4)
				binary.LittleEndian.PutUint32(b, uint32(now))
				return binary.LittleEndian.AppendUint32(b, 0x00000000)
			}()
			// 前回Send分が残ってると計算誤るため
			icmp.Checksum = 0x0
			icmp.Checksum = func() uint16 {
				b := make([]byte, 2)
				binary.LittleEndian.PutUint16(b, icmp.CalculateChecksum())
				return binary.BigEndian.Uint16(b)
			}()
			ipv4.Data = icmp.Bytes()
			ipv4.CalculateTotalLength()
			// 前回Send分が残ってると計算誤るため
			ipv4.HeaderChecksum = 0x0
			ipv4.CalculateChecksum()
			ethernetFrame := &packemon.EthernetFrame{
				Header: ethernetHeader,
				Data:   ipv4.Bytes(),
			}
			if err := sendFn(ethernetFrame); err != nil {
				t.app.Stop()
			}
		}).
		AddButton("Prev", func() {
			t.pages.SwitchToPage("IPv4")
		}).
		AddButton("Quit", func() {
			t.app.Stop()
		})

	return icmpForm
}

func (t *tui) ipv4Form(sendFn func(*packemon.EthernetFrame) error, ethernetHeader *packemon.EthernetHeader, ipv4 *packemon.IPv4) *tview.Form {
	ipv4Form := tview.NewForm().
		AddTextView("IPv4 Header", "This section generates the IPv4 header.\nIt is still under development.", 60, 4, true, false).
		AddInputField("Version(hex)", "0x04", 4, func(textToCheck string, lastChar rune) bool {
			if len(textToCheck) < 4 {
				return true
			} else if len(textToCheck) > 4 {
				return false
			}

			b, err := strHexToBytes(textToCheck)
			if err != nil {
				return false
			}
			ipv4.Version = uint8(binary.BigEndian.Uint16(b))

			return true
		}, nil).
		AddDropDown("Protocol", []string{"ICMP", "UDP"}, 0, func(selected string, _ int) {
			switch selected {
			case "ICMP":
				ipv4.Protocol = packemon.IPv4_PROTO_ICMP
			case "UDP":
				ipv4.Protocol = packemon.IPv4_PROTO_UDP
			}
		}).
		AddInputField("Source IP Addr", DEFAULT_IP_SOURCE, 15, func(textToCheck string, lastChar rune) bool {
			count := strings.Count(textToCheck, ".")
			if count < 3 {
				return true
			} else if count == 3 {
				ip, err := StrIPToBytes(textToCheck)
				if err != nil {
					return false
				}
				ipv4.SrcAddr = binary.BigEndian.Uint32(ip)
				return true
			}

			return false
		}, nil).
		AddInputField("Destination IP Addr", DEFAULT_IP_DESTINATION, 15, func(textToCheck string, lastChar rune) bool {
			count := strings.Count(textToCheck, ".")
			if count < 3 {
				return true
			} else if count == 3 {
				ip, err := StrIPToBytes(textToCheck)
				if err != nil {
					return false
				}
				ipv4.DstAddr = binary.BigEndian.Uint32(ip)
				return true
			}

			return false
		}, nil).
		AddButton("Send!", func() {
			ethernetFrame := &packemon.EthernetFrame{
				Header: ethernetHeader,
				Data:   ipv4.Bytes(),
			}
			if err := sendFn(ethernetFrame); err != nil {
				t.app.Stop()
			}
		}).
		AddButton("Next", func() {
			switch ipv4.Protocol {
			case packemon.IPv4_PROTO_ICMP:
				t.pages.SwitchToPage("ICMP")
			case packemon.IPv4_PROTO_UDP:
				// TODO:
				// pages.SwitchToPage("UDP")
			}
		}).
		AddButton("Prev", func() {
			t.pages.SwitchToPage("Ethernet")
		}).
		AddButton("Quit", func() {
			t.app.Stop()
		})

	return ipv4Form
}

func (t *tui) arpForm(sendFn func(*packemon.EthernetFrame) error, ethernetHeader *packemon.EthernetHeader, arp *packemon.ARP) *tview.Form {
	arpForm := tview.NewForm().
		AddTextView("ARP", "This section generates the ARP.\nIt is still under development.", 60, 4, true, false).
		AddInputField("Hardware Type(hex)", DEFAULT_ARP_HARDWARE_TYPE, 6, func(textToCheck string, lastChar rune) bool {
			if len(textToCheck) < 6 {
				return true
			} else if len(textToCheck) > 6 {
				return false
			}

			b, err := strHexToBytes2(textToCheck)
			if err != nil {
				return false
			}
			arp.HardwareType = [2]byte(b)

			return true
		}, nil).
		AddInputField("Protocol Type(hex)", DEFAULT_ARP_PROTOCOL_TYPE, 6, func(textToCheck string, lastChar rune) bool {
			if len(textToCheck) < 6 {
				return true
			} else if len(textToCheck) > 6 {
				return false
			}

			b, err := strHexToBytes2(textToCheck)
			if err != nil {
				return false
			}
			arp.ProtocolType = binary.BigEndian.Uint16(b)

			return true
		}, nil).
		AddInputField("Hardware Size(hex)", DEFAULT_ARP_HARDWARE_SIZE, 4, func(textToCheck string, lastChar rune) bool {
			if len(textToCheck) < 4 {
				return true
			} else if len(textToCheck) > 4 {
				return false
			}

			b, err := strHexToUint8(textToCheck)
			if err != nil {
				return false
			}
			arp.HardwareAddrLength = b

			return true
		}, nil).
		AddInputField("Protocol Size(hex)", DEFAULT_ARP_PROTOCOL_SIZE, 4, func(textToCheck string, lastChar rune) bool {
			if len(textToCheck) < 4 {
				return true
			} else if len(textToCheck) > 4 {
				return false
			}

			b, err := strHexToUint8(textToCheck)
			if err != nil {
				return false
			}
			arp.ProtocolLength = b

			return true
		}, nil).
		AddInputField("Operation Code(hex)", DEFAULT_ARP_OPERATION, 6, func(textToCheck string, lastChar rune) bool {
			if len(textToCheck) < 6 {
				return true
			} else if len(textToCheck) > 6 {
				return false
			}

			b, err := strHexToBytes2(textToCheck)
			if err != nil {
				return false
			}
			arp.Operation = [2]byte(b)

			return true
		}, nil).
		AddInputField("Sender Mac Addr(hex)", DEFAULT_ARP_SENDER_MAC, 14, func(textToCheck string, lastChar rune) bool {
			if len(textToCheck) < 14 {
				return true
			} else if len(textToCheck) > 14 {
				return false
			}

			b, err := strHexToBytes(textToCheck)
			if err != nil {
				return false
			}
			arp.SenderHardwareAddr = packemon.HardwareAddr(b)

			return true
		}, nil).
		AddInputField("Sender IP Addr", DEFAULT_ARP_SENDER_IP, 15, func(textToCheck string, lastChar rune) bool {
			count := strings.Count(textToCheck, ".")
			if count < 3 {
				return true
			} else if count == 3 {
				ip, err := StrIPToBytes(textToCheck)
				if err != nil {
					return false
				}

				arp.SenderIPAddr = [4]byte(ip)
				return true
			}

			return false
		}, nil).
		AddInputField("Target Mac Addr(hex)", DEFAULT_ARP_TARGET_MAC, 14, func(textToCheck string, lastChar rune) bool {
			if len(textToCheck) < 14 {
				return true
			} else if len(textToCheck) > 14 {
				return false
			}

			b, err := strHexToBytes(textToCheck)
			if err != nil {
				return false
			}
			arp.TargetHardwareAddr = packemon.HardwareAddr(b)

			return true
		}, nil).
		AddInputField("Target IP Addr", DEFAULT_ARP_TARGET_IP, 15, func(textToCheck string, lastChar rune) bool {
			count := strings.Count(textToCheck, ".")
			if count < 3 {
				return true
			} else if count == 3 {
				ip, err := StrIPToBytes(textToCheck)
				if err != nil {
					return false
				}

				arp.TargetIPAddr = [4]byte(ip)
				return true
			}

			return false
		}, nil).
		AddButton("Send!", func() {
			ethernetFrame := &packemon.EthernetFrame{
				Header: ethernetHeader,
				Data:   arp.Bytes(),
			}
			if err := sendFn(ethernetFrame); err != nil {
				t.app.Stop()
			}
		}).
		AddButton("Prev", func() {
			t.pages.SwitchToPage("Ethernet")
		}).
		AddButton("Quit", func() {
			t.app.Stop()
		})

	return arpForm
}

func (t *tui) ethernetForm(sendFn func(*packemon.EthernetFrame) error, ethernetHeader *packemon.EthernetHeader) *tview.Form {
	ethernetForm := tview.NewForm().
		AddTextView("Ethernet Header", "This section generates the Ethernet header.\nIt is still under development.", 60, 4, true, false).
		AddInputField("Destination Mac Addr(hex)", DEFAULT_MAC_DESTINATION, 14, func(textToCheck string, lastChar rune) bool {
			if len(textToCheck) < 14 {
				return true
			} else if len(textToCheck) > 14 {
				return false
			}

			b, err := strHexToBytes(textToCheck)
			if err != nil {
				return false
			}
			ethernetHeader.Dst = packemon.HardwareAddr(b)

			return true
		}, nil).
		AddInputField("Source Mac Addr(hex)", DEFAULT_MAC_SOURCE, 14, func(textToCheck string, lastChar rune) bool {
			if len(textToCheck) < 14 {
				return true
			} else if len(textToCheck) > 14 {
				return false
			}

			b, err := strHexToBytes(textToCheck)
			if err != nil {
				return false
			}
			ethernetHeader.Src = packemon.HardwareAddr(b)

			return true
		}, nil).
		// TODO: 自由にフレーム作れるとするなら、ここもhexで受け付けるようにして、IP or ARPヘッダフォームへの切り替えも自由にできた方がいいかも
		AddDropDown("Ether Type", []string{"IPv4", "ARP"}, 0, func(selected string, _ int) {
			switch selected {
			case "IPv4":
				ethernetHeader.Typ = packemon.ETHER_TYPE_IPv4
			case "ARP":
				ethernetHeader.Typ = packemon.ETHER_TYPE_ARP
			}
		}).
		AddButton("Send!", func() {
			ethernetFrame := &packemon.EthernetFrame{
				Header: ethernetHeader,
				// data: 専用の口用意してユーザー自身の任意のフレームを送れるようにする？,
			}
			if err := sendFn(ethernetFrame); err != nil {
				t.app.Stop()
			}
		}).
		AddButton("Next", func() {
			switch ethernetHeader.Typ {
			case packemon.ETHER_TYPE_IPv4:
				t.pages.SwitchToPage("IPv4")
			case packemon.ETHER_TYPE_ARP:
				t.pages.SwitchToPage("ARP")
			}
		}).
		AddButton("Quit", func() {
			t.app.Stop()
		})

	return ethernetForm
}
