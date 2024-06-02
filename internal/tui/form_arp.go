package tui

import (
	"encoding/binary"
	"strings"

	"github.com/ddddddO/packemon"
	"github.com/rivo/tview"
)

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
			arp.HardwareType = binary.BigEndian.Uint16(b)

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
			arp.Operation = binary.BigEndian.Uint16(b)

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
				ip, err := strIPToBytes(textToCheck)
				if err != nil {
					return false
				}

				arp.SenderIPAddr = binary.BigEndian.Uint32(ip)
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
				ip, err := strIPToBytes(textToCheck)
				if err != nil {
					return false
				}

				arp.TargetIPAddr = binary.BigEndian.Uint32(ip)
				return true
			}

			return false
		}, nil).
		AddButton("List", func() {
			t.app.SetFocus(t.list)
		}).
		AddButton("Send!", func() {
			ethernetFrame := &packemon.EthernetFrame{
				Header: ethernetHeader,
				Data:   arp.Bytes(),
			}
			if err := sendFn(ethernetFrame); err != nil {
				t.addErrPage(err)
			}
		}).
		AddButton("Under layer", func() {
			t.pages.SwitchToPage("Ethernet")
		}).
		AddButton("Quit", func() {
			t.app.Stop()
		})

	return arpForm
}
