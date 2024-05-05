package main

import (
	"encoding/binary"
	"strconv"
	"strings"
	"time"

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
func form(sendFn func(*EthernetFrame) error) error {
	app := tview.NewApplication()
	pages := tview.NewPages()
	pages.Box = tview.NewBox().SetTitle(" Packemon [Make & Send packet] ").SetBorder(true)
	ethernetHeader, arp, ipv4, icmp, err := defaultPackets()
	if err != nil {
		return err
	}

	icmpForm := icmpForm(app, pages, sendFn, ethernetHeader, ipv4, icmp)
	icmpForm.SetBorder(true).SetTitle(" ICMP ").SetTitleAlign(tview.AlignLeft)
	ipv4Form := ipv4Form(app, pages, sendFn, ethernetHeader, ipv4)
	ipv4Form.SetBorder(true).SetTitle(" IPv4 Header ").SetTitleAlign(tview.AlignLeft)
	arpForm := arpForm(app, pages, sendFn, ethernetHeader, arp)
	arpForm.SetBorder(true).SetTitle(" ARP ").SetTitleAlign(tview.AlignLeft)
	ethernetForm := ethernetForm(app, pages, sendFn, ethernetHeader)
	ethernetForm.SetBorder(true).SetTitle(" Ethernet Header ").SetTitleAlign(tview.AlignLeft)

	pages.
		AddPage("ICMP", icmpForm, true, true).
		AddPage("ARP", arpForm, true, true).
		AddPage("IPv4", ipv4Form, true, true).
		AddPage("Ethernet", ethernetForm, true, true)

	if err := app.SetRoot(pages, true).EnableMouse(true).Run(); err != nil {
		return err
	}

	return nil
}

func defaultPackets() (*EthernetHeader, *ARP, *ipv4, *icmp, error) {
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
	icmp := &icmp{
		typ:        icmpType,
		code:       icmpCode,
		identifier: binary.BigEndian.Uint16(icmpIdentifier),
		sequence:   binary.BigEndian.Uint16(icmpSequence),
	}

	ip, err := strIPToBytes(DEFAULT_IP_SOURCE)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	ipv4 := &ipv4{
		version:        0x04,
		ihl:            0x05,
		tos:            0x00,
		totalLength:    0x14,
		identification: 0xe31f,
		flags:          0x40,
		fragmentOffset: 0x0,
		ttl:            0x80,
		protocol:       IPv4_PROTO_ICMP,
		headerChecksum: 0,
		srcAddr:        binary.BigEndian.Uint32(ip),
		dstAddr:        binary.BigEndian.Uint32(ip),
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

	arp := &ARP{
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
	ethernetHeader := &EthernetHeader{
		Dst: HardwareAddr(mac),
		Src: HardwareAddr(mac),
		Typ: ETHER_TYPE_IPv4,
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

func icmpForm(app *tview.Application, pages *tview.Pages, sendFn func(*EthernetFrame) error, ethernetHeader *EthernetHeader, ipv4 *ipv4, icmp *icmp) *tview.Form {
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
			icmp.typ = uint8(b)

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
			icmp.code = uint8(b)

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
			icmp.identifier = binary.BigEndian.Uint16(b)

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
			icmp.sequence = binary.BigEndian.Uint16(b)

			return true
		}, nil).
		AddButton("Send!", func() {
			// TODO: timestamp関数化
			icmp.data = func() []byte {
				now := time.Now().Unix()
				b := make([]byte, 4)
				binary.LittleEndian.PutUint32(b, uint32(now))
				return binary.LittleEndian.AppendUint32(b, 0x00000000)
			}()
			// 前回Send分が残ってると計算誤るため
			icmp.checksum = 0x0
			icmp.checksum = func() uint16 {
				b := make([]byte, 2)
				binary.LittleEndian.PutUint16(b, icmp.calculateChecksum())
				return binary.BigEndian.Uint16(b)
			}()
			ipv4.data = icmp.toBytes()
			ipv4.calculateTotalLength()
			// 前回Send分が残ってると計算誤るため
			ipv4.headerChecksum = 0x0
			ipv4.calculateChecksum()
			ethernetFrame := &EthernetFrame{
				Header: ethernetHeader,
				Data:   ipv4.toBytes(),
			}
			if err := sendFn(ethernetFrame); err != nil {
				app.Stop()
			}
		}).
		AddButton("Prev", func() {
			pages.SwitchToPage("IPv4")
		}).
		AddButton("Quit", func() {
			app.Stop()
		})

	return icmpForm
}

func ipv4Form(app *tview.Application, pages *tview.Pages, sendFn func(*EthernetFrame) error, ethernetHeader *EthernetHeader, ipv4 *ipv4) *tview.Form {
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
			ipv4.version = uint8(binary.BigEndian.Uint16(b))

			return true
		}, nil).
		AddDropDown("Protocol", []string{"ICMP", "UDP"}, 0, func(selected string, _ int) {
			switch selected {
			case "ICMP":
				ipv4.protocol = IPv4_PROTO_ICMP
			case "UDP":
				ipv4.protocol = IPv4_PROTO_UDP
			}
		}).
		AddInputField("Source IP Addr", DEFAULT_IP_SOURCE, 15, func(textToCheck string, lastChar rune) bool {
			count := strings.Count(textToCheck, ".")
			if count < 3 {
				return true
			} else if count == 3 {
				ip, err := strIPToBytes(textToCheck)
				if err != nil {
					return false
				}
				ipv4.srcAddr = binary.BigEndian.Uint32(ip)
				return true
			}

			return false
		}, nil).
		AddInputField("Destination IP Addr", DEFAULT_IP_DESTINATION, 15, func(textToCheck string, lastChar rune) bool {
			count := strings.Count(textToCheck, ".")
			if count < 3 {
				return true
			} else if count == 3 {
				ip, err := strIPToBytes(textToCheck)
				if err != nil {
					return false
				}
				ipv4.dstAddr = binary.BigEndian.Uint32(ip)
				return true
			}

			return false
		}, nil).
		AddButton("Send!", func() {
			ethernetFrame := &EthernetFrame{
				Header: ethernetHeader,
				Data:   ipv4.toBytes(),
			}
			if err := sendFn(ethernetFrame); err != nil {
				app.Stop()
			}
		}).
		AddButton("Next", func() {
			switch ipv4.protocol {
			case IPv4_PROTO_ICMP:
				pages.SwitchToPage("ICMP")
			case IPv4_PROTO_UDP:
				// TODO:
				// pages.SwitchToPage("UDP")
			}
		}).
		AddButton("Prev", func() {
			pages.SwitchToPage("Ethernet")
		}).
		AddButton("Quit", func() {
			app.Stop()
		})

	return ipv4Form
}

func arpForm(app *tview.Application, pages *tview.Pages, sendFn func(*EthernetFrame) error, ethernetHeader *EthernetHeader, arp *ARP) *tview.Form {
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
			arp.SenderHardwareAddr = HardwareAddr(b)

			return true
		}, nil).
		AddInputField("Sender IP Addr", DEFAULT_ARP_SENDER_IP, 15, func(textToCheck string, lastChar rune) bool {
			count := strings.Count(textToCheck, ".")
			if count < 3 {
				return true
			} else if count == 3 {
				ip, err := strIPToBytes(textToCheck)
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
			arp.TargetHardwareAddr = HardwareAddr(b)

			return true
		}, nil).
		AddInputField("Target IP Addr", DEFAULT_ARP_TARGET_IP, 15, func(textToCheck string, lastChar rune) bool {
			count := strings.Count(textToCheck, ".")
			if count < 3 {
				return true
			} else if count == 3 {
				ip, err := strIPToBytes(textToCheck)
				if err != nil {
					return false
				}

				arp.TargetIPAddr = [4]byte(ip)
				return true
			}

			return false
		}, nil).
		AddButton("Send!", func() {
			ethernetFrame := &EthernetFrame{
				Header: ethernetHeader,
				Data:   arp.Bytes(),
			}
			if err := sendFn(ethernetFrame); err != nil {
				app.Stop()
			}
		}).
		AddButton("Prev", func() {
			pages.SwitchToPage("Ethernet")
		}).
		AddButton("Quit", func() {
			app.Stop()
		})

	return arpForm
}

func ethernetForm(app *tview.Application, pages *tview.Pages, sendFn func(*EthernetFrame) error, ethernetHeader *EthernetHeader) *tview.Form {
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
			ethernetHeader.Dst = HardwareAddr(b)

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
			ethernetHeader.Src = HardwareAddr(b)

			return true
		}, nil).
		// TODO: 自由にフレーム作れるとするなら、ここもhexで受け付けるようにして、IP or ARPヘッダフォームへの切り替えも自由にできた方がいいかも
		AddDropDown("Ether Type", []string{"IPv4", "ARP"}, 0, func(selected string, _ int) {
			switch selected {
			case "IPv4":
				ethernetHeader.Typ = ETHER_TYPE_IPv4
			case "ARP":
				ethernetHeader.Typ = ETHER_TYPE_ARP
			}
		}).
		AddButton("Send!", func() {
			ethernetFrame := &EthernetFrame{
				Header: ethernetHeader,
				// data: 専用の口用意してユーザー自身の任意のフレームを送れるようにする？,
			}
			if err := sendFn(ethernetFrame); err != nil {
				app.Stop()
			}
		}).
		AddButton("Next", func() {
			switch ethernetHeader.Typ {
			case ETHER_TYPE_IPv4:
				pages.SwitchToPage("IPv4")
			case ETHER_TYPE_ARP:
				pages.SwitchToPage("ARP")
			}
		}).
		AddButton("Quit", func() {
			app.Stop()
		})

	return ethernetForm
}
