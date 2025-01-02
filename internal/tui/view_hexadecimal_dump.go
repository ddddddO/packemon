package tui

import (
	"github.com/ddddddO/packemon"
	"github.com/rivo/tview"
)

type HexadecimalDump struct {
	*packemon.EthernetFrame
	*packemon.ARP
	*packemon.IPv4
	*packemon.IPv6
	*packemon.ICMP
	*packemon.TCP
	*packemon.UDP
	*packemon.DNS
	*packemon.HTTP
	*packemon.HTTPResponse

	data []byte
}

func (h *HexadecimalDump) rows() int {
	return 20
}

func (*HexadecimalDump) columns() int {
	return 30
}

// TODO: 似た構造あるからそこ共通化
func (h *HexadecimalDump) viewTable() *tview.Table {
	table := tview.NewTable().SetBorders(false)
	table.Box = tview.NewBox().SetBorder(true).SetTitle(" Hexadecimal dump ").SetTitleAlign(tview.AlignLeft).SetBorderPadding(1, 1, 1, 1)

	// L2
	switch {
	case h.EthernetFrame != nil:
		const ethernetHeaderLength = 14
		table.SetCell(0, 0, tview.NewTableCell(padding("Ethernet")))
		table.SetCell(0, 1, tview.NewTableCell(padding(spacer(h.EthernetFrame.Bytes()[0:ethernetHeaderLength]))))
	}

	// L3
	loopForL3View := 1
	switch {
	case h.ARP != nil:
		table.SetCell(loopForL3View, 0, tview.NewTableCell(padding("ARP")))

		arpBytes := h.ARP.Bytes()
		for i := 0; ; i += 16 {
			if len(arpBytes) < i+16 {
				table.SetCell(loopForL3View, 1, tview.NewTableCell(padding(spacer(arpBytes[i:]))))
				break
			}
			table.SetCell(loopForL3View, 1, tview.NewTableCell(padding(spacer(arpBytes[i:i+16]))))

			loopForL3View++
		}

	case h.IPv4 != nil:
		table.SetCell(loopForL3View, 0, tview.NewTableCell(padding("IPv4")))

		ipv4Bytes := h.IPv4.Bytes()[0 : h.IPv4.Ihl*4]
		for i := 0; ; i += 16 {
			if len(ipv4Bytes) < i+16 {
				table.SetCell(loopForL3View, 1, tview.NewTableCell(padding(spacer(ipv4Bytes[i:]))))
				break
			}
			table.SetCell(loopForL3View, 1, tview.NewTableCell(padding(spacer(ipv4Bytes[i:i+16]))))

			loopForL3View++
		}

	case h.IPv6 != nil:
		table.SetCell(loopForL3View, 0, tview.NewTableCell(padding("IPv6")))
		// TODO: IPv6.Bytes()
		// table.SetCell(loopForL3View, 1, tview.NewTableCell(padding(spacer("%x", h.IPv6)))
	}

	// L4
	const udpHeaderLength = 8
	loopForL4View := 1 + loopForL3View
	switch {
	case h.ICMP != nil:
		table.SetCell(loopForL4View, 0, tview.NewTableCell(padding("ICMP")))

		icmpBytes := h.ICMP.Bytes()
		for i := 0; ; i += 16 {
			if len(icmpBytes) < i+16 {
				table.SetCell(loopForL4View, 1, tview.NewTableCell(padding(spacer(icmpBytes[i:]))))
				break
			}
			table.SetCell(loopForL4View, 1, tview.NewTableCell(padding(spacer(icmpBytes[i:i+16]))))

			loopForL4View++
		}

	case h.TCP != nil:
		table.SetCell(loopForL4View, 0, tview.NewTableCell(padding("TCP")))

		tcpBytes := h.TCP.Bytes()[0 : h.TCP.HeaderLength/4]
		for i := 0; ; i += 16 {
			if len(tcpBytes) < i+16 {
				table.SetCell(loopForL4View, 1, tview.NewTableCell(padding(spacer(tcpBytes[i:]))))
				break
			} else {
				table.SetCell(loopForL4View, 1, tview.NewTableCell(padding(spacer(tcpBytes[i:i+16]))))
			}
			loopForL4View++
		}
	case h.UDP != nil:
		table.SetCell(loopForL4View, 0, tview.NewTableCell(padding("UDP")))
		table.SetCell(loopForL4View, 1, tview.NewTableCell(padding(spacer(h.UDP.Bytes()[0:udpHeaderLength]))))
	}

	// L7
	loopForL7View := 1 + loopForL4View
	switch {
	case h.DNS != nil:
		table.SetCell(loopForL7View, 0, tview.NewTableCell(padding("DNS")))
		if h.UDP != nil {
			dnsBytes := h.DNS.Bytes()[0 : h.UDP.Length-udpHeaderLength]
			for i := 0; ; i += 16 {
				if len(dnsBytes) < i+16 {
					table.SetCell(loopForL7View, 1, tview.NewTableCell(padding(spacer(dnsBytes[i:]))))
					break
				} else {
					table.SetCell(loopForL7View, 1, tview.NewTableCell(padding(spacer(dnsBytes[i:i+16]))))
				}

				loopForL7View++
			}

		}
		if h.TCP != nil {
			// TODO:
		}
	case h.HTTP != nil:
		table.SetCell(loopForL7View, 0, tview.NewTableCell(padding("HTTP")))

		httpBytes := h.HTTP.Bytes()
		for i := 0; ; i += 16 {
			if len(httpBytes) < i+16 {
				table.SetCell(loopForL7View, 1, tview.NewTableCell(padding(spacer(httpBytes[i:]))))
				break
			} else {
				table.SetCell(loopForL7View, 1, tview.NewTableCell(padding(spacer(httpBytes[i:i+16]))))
			}

			loopForL7View++
		}

	case h.HTTPResponse != nil:
		table.SetCell(loopForL7View, 0, tview.NewTableCell(padding("HTTP")))
		// TODO: HTTPResponse.Bytes()
		// table.SetCell(loopForL7View, 1, tview.NewTableCell(padding(spacer(h.HTTPResponse)))
	}

	return table
}
