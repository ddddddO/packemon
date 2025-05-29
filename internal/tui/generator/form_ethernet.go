package generator

import (
	"context"
	"fmt"
	"strings"

	"github.com/ddddddO/packemon"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

var underIPv6 = false

// MACValidationResult contains the result of MAC address validation
type MACValidationResult struct {
	Address   packemon.HardwareAddr
	HasAddress bool  // indicates whether Address contains a valid parsed address
	Valid     bool
	Error     string
}

// validateAndParseMACAddress validates and parses MAC address input
// Supports hex format (0x prefix), colon-separated, and dash-separated formats
func validateAndParseMACAddress(input string) MACValidationResult {
	l := len(input)
	
	if l > 20 {
		return MACValidationResult{
			Valid: false,
			Error: "MAC address too long (max 20 characters)",
		}
	}

	// Only try to parse when we have enough characters for a potential MAC address
	// Minimum: "0x" + 12 hex chars = 14, or XX:XX:XX:XX:XX:XX = 17, or XX-XX-XX-XX-XX-XX = 17
	if l >= 14 || ((strings.Contains(input, ":") || strings.Contains(input, "-")) && l >= 17) {
		var b []byte
		var err error
		
		if strings.Contains(input, ":") || strings.Contains(input, "-") {
			// Remove colons or dashes
			cleaned := strings.ReplaceAll(input, ":", "")
			cleaned = strings.ReplaceAll(cleaned, "-", "")
			
			if len(cleaned) > 12 {
				return MACValidationResult{
					Valid: false,
					Error: "Invalid MAC address format",
				}
			}
			
			// Validate hex characters
			for _, c := range cleaned {
				if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
					return MACValidationResult{
						Valid: true, // Allow continued typing
						Error: fmt.Sprintf("Invalid character: %c", c),
					}
				}
			}
			
			b, err = packemon.StrHexToBytes("0x" + cleaned)
		} else {
			b, err = packemon.StrHexToBytes(input)
		}
		
		if err != nil {
			return MACValidationResult{
				Valid: true, // Allow continued typing
				Error: "Invalid hex format",
			}
		}
		
		var addr packemon.HardwareAddr
		copy(addr[:], b)
		
		return MACValidationResult{
			Address:    addr,
			HasAddress: true,
			Valid:      true,
		}
	}

	return MACValidationResult{
		Valid: true, // Allow continued typing
	}
}

func (g *generator) ethernetForm() *tview.Form {
	// Status labels for MAC address validation feedback
	dstMACStatus := tview.NewTextView().
		SetDynamicColors(true).
		SetText("")
	
	srcMACStatus := tview.NewTextView().
		SetDynamicColors(true).
		SetText("")

	ethernetForm := tview.NewForm().
		AddTextView("Ethernet Header", "This section generates the Ethernet header.\nIt is still under development.", 60, 4, true, false).
		AddInputField("Destination Mac Addr(hex)", DEFAULT_MAC_DESTINATION, 20, func(textToCheck string, lastChar rune) bool {
			// Support hex (0x), colon-separated, and dash-separated formats
			result := validateAndParseMACAddress(textToCheck)
			
			// Update status message
			if result.Error != "" {
				dstMACStatus.SetText(fmt.Sprintf("[red]%s[white]", result.Error))
			} else if result.HasAddress {
				dstMACStatus.SetText("[green]Valid MAC address[white]")
				g.sender.packets.ethernet.Dst = result.Address
			} else {
				dstMACStatus.SetText("")
			}
			
			return result.Valid
		}, nil).
		AddFormItem(dstMACStatus).
		AddInputField("Source Mac Addr(hex)", DEFAULT_MAC_SOURCE, 20, func(textToCheck string, lastChar rune) bool {
			// Support hex (0x), colon-separated, and dash-separated formats
			result := validateAndParseMACAddress(textToCheck)
			
			// Update status message
			if result.Error != "" {
				srcMACStatus.SetText(fmt.Sprintf("[red]%s[white]", result.Error))
			} else if result.HasAddress {
				srcMACStatus.SetText("[green]Valid MAC address[white]")
				g.sender.packets.ethernet.Src = result.Address
			} else {
				srcMACStatus.SetText("")
			}
			
			return result.Valid
		}, nil).
		AddFormItem(srcMACStatus).
		// TODO: 自由にフレーム作れるとするなら、ここもhexで受け付けるようにして、IP or ARPヘッダフォームへの切り替えも自由にできた方がいいかも
		AddDropDown("Ether Type", []string{"IPv4", "IPv6", "ARP"}, 0, func(selected string, _ int) {
			switch selected {
			case "IPv4":
				g.sender.packets.ethernet.Typ = packemon.ETHER_TYPE_IPv4
				underIPv6 = false
			case "IPv6":
				g.sender.packets.ethernet.Typ = packemon.ETHER_TYPE_IPv6
				underIPv6 = true
			case "ARP":
				g.sender.packets.ethernet.Typ = packemon.ETHER_TYPE_ARP
				underIPv6 = false
			}
		}).
		AddButton("Send!", func() {
			if err := g.sender.sendLayer2(context.TODO()); err != nil {
				g.addErrPage(err)
			}
		}).
		AddButton("Quit", func() {
			g.app.Stop()
		})

	// Set field colors to indicate validation state
	ethernetForm.SetFieldBackgroundColor(tcell.ColorBlack)
	ethernetForm.SetFieldTextColor(tcell.ColorWhite)

	return ethernetForm
}
