package main

import (
	"encoding/binary"
	"strconv"
	"strings"

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

	DEAFULT_IP_SOURCE      = ""
	DEFAULT_IP_DESTINATION = ""
)

// 長さとか他のフィールドに基づいて計算しないといけない値があるから、そこは固定値ではなくてリアルタイムに反映したい
// とすると、高レイヤーの入力から埋めて進めていくようにしないといけなさそう. ユーザーが選べるようにするのがいいかも
func form(sendFn func(*ethernetFrame) error) error {
	app := tview.NewApplication()
	pages := tview.NewPages()
	pages.Box = tview.NewBox().SetTitle(" Packemon [Make & Send packet] ").SetBorder(true)
	ethernetHeader, arp, ipv4, err := defaultPackets()
	if err != nil {
		return err
	}

	ipv4Form := ipv4Form(app, pages, sendFn, ethernetHeader, ipv4)
	ipv4Form.SetBorder(true).SetTitle(" IPv4 Header ").SetTitleAlign(tview.AlignLeft)
	arpForm := arpForm(app, pages, sendFn, ethernetHeader, arp)
	arpForm.SetBorder(true).SetTitle(" ARP ").SetTitleAlign(tview.AlignLeft)
	ethernetForm := ethernetForm(app, pages, sendFn, ethernetHeader)
	ethernetForm.SetBorder(true).SetTitle(" Ethernet Header ").SetTitleAlign(tview.AlignLeft)

	pages.
		AddPage("ARP", arpForm, true, true).
		AddPage("IPv4", ipv4Form, true, true).
		AddPage("Ethernet", ethernetForm, true, true)

	if err := app.SetRoot(pages, true).EnableMouse(true).Run(); err != nil {
		return err
	}

	return nil
}

func defaultPackets() (*ethernetHeader, *arp, *ipv4, error) {
	ip, err := strIPToBytes(DEAFULT_IP_SOURCE)
	if err != nil {
		return nil, nil, nil, err
	}

	ipv4 := &ipv4{
		version:        0x04,
		ihl:            0x05,
		tos:            0x00,
		totalLength:    0x14,
		identification: 0xe31f,
		flags:          0x0,
		fragmentOffset: 0x0,
		ttl:            0x80,
		protocol:       0x11,
		headerChecksum: 0x0f55,
		srcAddr:        binary.BigEndian.Uint32(ip),
		dstAddr:        binary.BigEndian.Uint32(ip),
	}

	hardwareType, err := strHexToBytes2(DEFAULT_ARP_HARDWARE_TYPE)
	if err != nil {
		return nil, nil, nil, err
	}
	protocolType, err := strHexToBytes2(DEFAULT_ARP_PROTOCOL_TYPE)
	if err != nil {
		return nil, nil, nil, err
	}
	hardwareSize, err := strHexToUint8(DEFAULT_ARP_HARDWARE_SIZE)
	if err != nil {
		return nil, nil, nil, err
	}
	protocolSize, err := strHexToUint8(DEFAULT_ARP_PROTOCOL_SIZE)
	if err != nil {
		return nil, nil, nil, err
	}
	operation, err := strHexToBytes2(DEFAULT_ARP_OPERATION)
	if err != nil {
		return nil, nil, nil, err
	}
	senderMac, err := strHexToBytes(DEFAULT_ARP_SENDER_MAC)
	if err != nil {
		return nil, nil, nil, err
	}
	senderIP, err := strIPToBytes(DEFAULT_ARP_SENDER_IP)
	if err != nil {
		return nil, nil, nil, err
	}

	arp := &arp{
		hardwareType:       [2]byte(hardwareType),
		protocolType:       binary.BigEndian.Uint16(protocolType),
		hardwareAddrLength: hardwareSize,
		protocolLength:     protocolSize,
		operation:          [2]byte(operation),

		senderHardwareAddr: [6]byte(senderMac),
		senderIPAddr:       [4]byte(senderIP),

		targetHardwareAddr: [6]uint8{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		targetIPAddr:       [4]byte{0x08, 0x08, 0x08, 0x08},
	}

	mac, err := strHexToBytes(DEFAULT_MAC_SOURCE)
	if err != nil {
		return nil, nil, nil, err
	}
	ethernetHeader := &ethernetHeader{
		dst: hardwareAddr(mac),
		src: hardwareAddr(mac),
		typ: ETHER_TYPE_IPv4,
	}

	return ethernetHeader, arp, ipv4, nil
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

func ipv4Form(app *tview.Application, pages *tview.Pages, sendFn func(*ethernetFrame) error, ethernetHeader *ethernetHeader, ipv4 *ipv4) *tview.Form {
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
		AddInputField("Source IP Addr", DEAFULT_IP_SOURCE, 15, func(textToCheck string, lastChar rune) bool {
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
			ethernetFrame := &ethernetFrame{
				header: ethernetHeader,
				data:   ipv4.toBytes(),
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

	return ipv4Form
}

func arpForm(app *tview.Application, pages *tview.Pages, sendFn func(*ethernetFrame) error, ethernetHeader *ethernetHeader, arp *arp) *tview.Form {
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
			arp.hardwareType = [2]byte(b)

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
			arp.protocolType = binary.BigEndian.Uint16(b)

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
			arp.hardwareAddrLength = b

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
			arp.protocolLength = b

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
			arp.operation = [2]byte(b)

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
			arp.senderHardwareAddr = hardwareAddr(b)

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

				arp.senderIPAddr = [4]byte(ip)
				return true
			}

			return false
		}, nil).
		AddButton("Send!", func() {
			ethernetFrame := &ethernetFrame{
				header: ethernetHeader,
				data:   arp.toBytes(),
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

func ethernetForm(app *tview.Application, pages *tview.Pages, sendFn func(*ethernetFrame) error, ethernetHeader *ethernetHeader) *tview.Form {
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
			ethernetHeader.dst = hardwareAddr(b)

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
			ethernetHeader.src = hardwareAddr(b)

			return true
		}, nil).
		AddDropDown("Ether Type", []string{"IPv4", "ARP"}, 0, func(selected string, _ int) {
			switch selected {
			case "IPv4":
				ethernetHeader.typ = ETHER_TYPE_IPv4
			case "ARP":
				ethernetHeader.typ = ETHER_TYPE_ARP
			}
		}).
		AddButton("Send!", func() {
			ethernetFrame := &ethernetFrame{
				header: ethernetHeader,
				// data: 専用の口用意してユーザー自身の任意のフレームを送れるようにする？,
			}
			if err := sendFn(ethernetFrame); err != nil {
				app.Stop()
			}
		}).
		AddButton("Next", func() {
			switch ethernetHeader.typ {
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
