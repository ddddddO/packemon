package main

import (
	"encoding/binary"
	"strconv"
	"strings"

	"github.com/rivo/tview"
)

const (
	DEFAULT_MAC_DESTINATION = "0x00155df27ccb"
	DEFAULT_MAC_SOURCE      = "0xffffffffffff"
	DEFAULT_ETHER_TYPE      = "IPv4"

	DEAFULT_IP_SOURCE      = "192.168.99.88"
	DEFAULT_IP_DESTINATION = "192.168.99.1"
)

// 長さとか他のフィールドに基づいて計算しないといけない値があるから、そこは固定値ではなくてリアルタイムに反映したい
// とすると、高レイヤーの入力から埋めて進めていくようにしないといけなさそう
func form(sendFn func(*ethernetFrame) error) error {
	ethernetHeader, arp, ipv4 := defaultPackets()
	app := tview.NewApplication()
	pages := tview.NewPages()
	pages.Box = tview.NewBox().SetTitle(" Packemon [Make & Send packet] ").SetBorder(true)

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

	arpForm := tview.NewForm().
		AddTextView("ARP", "This section generates the ARP.\nIt is still under development.", 60, 4, true, false).
		// AddInputField("Version(hex)", "0x04", 4, func(textToCheck string, lastChar rune) bool {
		// 	if len(textToCheck) < 4 {
		// 		return true
		// 	} else if len(textToCheck) > 4 {
		// 		return false
		// 	}

		// 	b, err := strHexToBytes(textToCheck)
		// 	if err != nil {
		// 		return false
		// 	}
		// 	ipv4.version = uint8(binary.BigEndian.Uint16(b))

		// 	return true
		// }, nil).
		// AddInputField("Source IP Addr", DEAFULT_IP_SOURCE, 15, func(textToCheck string, lastChar rune) bool {
		// 	count := strings.Count(textToCheck, ".")
		// 	if count < 3 {
		// 		return true
		// 	} else if count == 3 {
		// 		ip, err := strIPToBytes(textToCheck)
		// 		if err != nil {
		// 			return false
		// 		}
		// 		ipv4.srcAddr = binary.BigEndian.Uint32(ip)
		// 		return true
		// 	}

		// 	return false
		// }, nil).
		// AddInputField("Destination IP Addr", DEFAULT_IP_DESTINATION, 15, func(textToCheck string, lastChar rune) bool {
		// 	count := strings.Count(textToCheck, ".")
		// 	if count < 3 {
		// 		return true
		// 	} else if count == 3 {
		// 		ip, err := strIPToBytes(textToCheck)
		// 		if err != nil {
		// 			return false
		// 		}
		// 		ipv4.dstAddr = binary.BigEndian.Uint32(ip)
		// 		return true
		// 	}

		// 	return false
		// }, nil).
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

	ethernetForm := tview.NewForm().
		// AddInputField("Last name", "", 20, nil, nil).
		// AddTextArea("Address", "", 40, 0, 0, nil).
		// AddTextView("Notes", "This is just a demo.\nYou can enter whatever you wish.", 40, 2, true, false).
		// AddCheckbox("Age 18+", false, nil).
		// AddPasswordField("Password", "", 10, '*', nil).
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
				pages.SwitchToPage("IPv4")
			case "ARP":
				ethernetHeader.typ = ETHER_TYPE_ARP
				pages.SwitchToPage("ARP")
			}
		})

	ethernetForm.SetBorder(true).SetTitle(" Ethernet Header ").SetTitleAlign(tview.AlignLeft)
	ipv4Form.SetBorder(true).SetTitle(" IPv4 Header ").SetTitleAlign(tview.AlignLeft)
	arpForm.SetBorder(true).SetTitle(" ARP ").SetTitleAlign(tview.AlignLeft)

	pages.
		AddPage("ARP", arpForm, true, true).
		AddPage("IPv4", ipv4Form, true, true).
		AddPage("Ethernet", ethernetForm, true, true)

	if err := app.SetRoot(pages, true).EnableMouse(true).Run(); err != nil {
		return err
	}

	return nil
}

func defaultPackets() (*ethernetHeader, *arp, *ipv4) {
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
		srcAddr:        0xc0a86358, // 192.168.99.88
		dstAddr:        0xc0a86301, // 192.168.99.1
	}

	arp := &arp{
		hardwareType:       [2]byte{0x00, 0x01},
		protocolType:       ETHER_TYPE_IPv4,
		hardwareAddrLength: 0x06,
		protocolLength:     0x04,
		operation:          [2]byte{0x00, 0x01},

		senderHardwareAddr: [6]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xff},
		senderIPAddr:       [4]byte{0xac, 0x17, 0xf2, 0x4e},

		targetHardwareAddr: [6]uint8{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		targetIPAddr:       [4]byte{0x08, 0x08, 0x08, 0x08},
	}

	ethernetHeader := &ethernetHeader{
		dst: hardwareAddr([6]byte{0x00, 0x15, 0x5d, 0xf2, 0x7c, 0xcb}),
		src: hardwareAddr([6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}),
		typ: ETHER_TYPE_IPv4,
	}

	return ethernetHeader, arp, ipv4
}

func strHexToBytes(s string) ([]byte, error) {
	n, err := strconv.ParseUint(s, 0, 48)
	if err != nil {
		return nil, err
	}

	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, n)
	return buf[2:], nil
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
