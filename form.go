package main

import (
	"encoding/binary"
	"strconv"
	"strings"

	"github.com/rivo/tview"
)

const (
	DEFAULT_ETHER_TYPE = "IPv4"
)

var (
	DEFAULT_MAC_DESTINATION = ""
	DEFAULT_MAC_SOURCE      = ""

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
		})

	return ethernetForm
}
