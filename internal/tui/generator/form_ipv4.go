package generator

import (
	"context"
	"encoding/binary"
	"strings"

	"github.com/ddddddO/packemon"
	"github.com/rivo/tview"
)

var checkedCalcIPv4TotalLength = true
var checkedCalcIPv4Checksum = true

func (g *generator) ipv4Form() *tview.Form {
	ipv4Form := tview.NewForm().
		AddTextView("IPv4 Header", "This section generates the IPv4 header.\nIt is still under development.", 60, 4, true, false).
		AddInputField("Version", "0x04", 4, func(textToCheck string, lastChar rune) bool {
			if len(textToCheck) < 4 {
				return true
			} else if len(textToCheck) > 4 {
				return false
			}

			b, err := packemon.StrHexToBytes(textToCheck)
			if err != nil {
				return false
			}
			g.sender.packets.ipv4.Version = uint8(binary.BigEndian.Uint16(b))

			return true
		}, nil).
		AddInputField("Internet Header Length", DEFAULT_IP_IHL, 4, func(textToCheck string, lastChar rune) bool {
			if len(textToCheck) < 4 {
				return true
			} else if len(textToCheck) > 4 {
				return false
			}

			b, err := strHexToUint8(textToCheck)
			if err != nil {
				return false
			}
			g.sender.packets.ipv4.Ihl = uint8(b)

			return true
		}, nil).
		AddInputField("Type of Service", DEFAULT_IP_TOS, 4, func(textToCheck string, lastChar rune) bool {
			if len(textToCheck) < 4 {
				return true
			} else if len(textToCheck) > 4 {
				return false
			}

			b, err := strHexToUint8(textToCheck)
			if err != nil {
				return false
			}
			g.sender.packets.ipv4.Tos = uint8(b)

			return true
		}, nil).
		AddCheckbox("Automatically calculate total length ?", checkedCalcIPv4TotalLength, func(checked bool) {
			checkedCalcIPv4TotalLength = checked
		}).
		AddInputField("Total Length", DEFAULT_IP_TOTAL_LENGTH, 6, func(textToCheck string, lastChar rune) bool {
			if len(textToCheck) < 6 {
				return true
			} else if len(textToCheck) > 6 {
				return false
			}

			b, err := packemon.StrHexToBytes2(textToCheck)
			if err != nil {
				return false
			}
			g.sender.packets.ipv4.TotalLength = binary.BigEndian.Uint16(b)

			return true
		}, nil).
		AddInputField("Identification", DEFAULT_IP_IDENTIFICATION, 6, func(textToCheck string, lastChar rune) bool {
			if len(textToCheck) < 6 {
				return true
			} else if len(textToCheck) > 6 {
				return false
			}

			b, err := packemon.StrHexToBytes2(textToCheck)
			if err != nil {
				return false
			}
			g.sender.packets.ipv4.Identification = binary.BigEndian.Uint16(b)

			return true
		}, nil).
		AddInputField("Flags", DEFAULT_IP_FLAGS, 4, func(textToCheck string, lastChar rune) bool {
			if len(textToCheck) < 4 {
				return true
			} else if len(textToCheck) > 4 {
				return false
			}

			b, err := strHexToUint8(textToCheck)
			if err != nil {
				return false
			}
			g.sender.packets.ipv4.Flags = uint8(b)

			return true
		}, nil).
		AddInputField("Fragment Offset", DEFAULT_IP_FRAGMENT_OFFSET, 6, func(textToCheck string, lastChar rune) bool {
			if len(textToCheck) < 6 {
				return true
			} else if len(textToCheck) > 6 {
				return false
			}

			b, err := packemon.StrHexToBytes2(textToCheck)
			if err != nil {
				return false
			}
			g.sender.packets.ipv4.FragmentOffset = binary.BigEndian.Uint16(b)

			return true
		}, nil).
		AddInputField("TTL", DEFAULT_IP_TTL, 4, func(textToCheck string, lastChar rune) bool {
			if len(textToCheck) < 4 {
				return true
			} else if len(textToCheck) > 4 {
				return false
			}

			b, err := strHexToUint8(textToCheck)
			if err != nil {
				return false
			}
			g.sender.packets.ipv4.Ttl = uint8(b)

			return true
		}, nil).
		AddDropDown("Protocol", []string{"ICMP", "UDP", "TCP"}, 1, func(selected string, _ int) {
			switch selected {
			case "ICMP":
				g.sender.packets.ipv4.Protocol = packemon.IPv4_PROTO_ICMP
			case "UDP":
				g.sender.packets.ipv4.Protocol = packemon.IPv4_PROTO_UDP
			case "TCP":
				g.sender.packets.ipv4.Protocol = packemon.IPv4_PROTO_TCP
			}
		}).
		AddCheckbox("Automatically calculate header checksum ?", checkedCalcIPv4Checksum, func(checked bool) {
			checkedCalcIPv4Checksum = checked
		}).
		AddInputField("Header Checksum", DEFAULT_IP_HEADER_CHECKSUM, 6, func(textToCheck string, lastChar rune) bool {
			if len(textToCheck) < 6 {
				return true
			} else if len(textToCheck) > 6 {
				return false
			}

			b, err := packemon.StrHexToBytes2(textToCheck)
			if err != nil {
				return false
			}
			g.sender.packets.ipv4.HeaderChecksum = binary.BigEndian.Uint16(b)

			return true
		}, nil).
		AddInputField("Source IP Addr", DEFAULT_IP_SOURCE, 15, func(textToCheck string, lastChar rune) bool {
			count := strings.Count(textToCheck, ".")
			if count < 3 {
				return true
			} else if count == 3 {
				ip, err := packemon.StrIPToBytes(textToCheck)
				if err != nil {
					return false
				}
				g.sender.packets.ipv4.SrcAddr = binary.BigEndian.Uint32(ip)
				return true
			}

			return false
		}, nil).
		AddInputField("Destination IP Addr", DEFAULT_IP_DESTINATION, 15, func(textToCheck string, lastChar rune) bool {
			count := strings.Count(textToCheck, ".")
			if count < 3 {
				return true
			} else if count == 3 {
				ip, err := packemon.StrIPToBytes(textToCheck)
				if err != nil {
					return false
				}
				g.sender.packets.ipv4.DstAddr = binary.BigEndian.Uint32(ip)
				return true
			}

			return false
		}, nil).
		AddButton("Send!", func() {
			if err := g.sender.sendLayer3(context.TODO()); err != nil {
				g.addErrPage(err)
			}
		}).
		AddButton("Quit", func() {
			g.app.Stop()
		})

	return ipv4Form
}
