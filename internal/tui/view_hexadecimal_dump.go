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
	*packemon.TLSClientHello
	*packemon.TLSServerHello
	*packemon.TLSServerHelloFor1_3
	*packemon.TLSClientKeyExchange
	*packemon.TLSChangeCipherSpecAndEncryptedHandshakeMessage
	*packemon.TLSApplicationData
	*packemon.TLSEncryptedAlert
	*packemon.DNS
	*packemon.HTTP
	*packemon.HTTPResponse

	data []byte
}

func (h *HexadecimalDump) rows() int {
	// TODO: データ量でよしなに決めたい
	// あと、スクロールなにか指定しないといけない？最後までスクロールできてないみたい
	return 200
}

func (*HexadecimalDump) columns() int {
	return 30
}

func (h *HexadecimalDump) viewTable() *tview.Table {
	table := tview.NewTable().SetBorders(false)
	table.Box = tview.NewBox().SetBorder(true).SetTitle(" Hexadecimal dump ").SetTitleAlign(tview.AlignLeft).SetBorderPadding(1, 1, 1, 1)

	// L2
	switch {
	case h.EthernetFrame != nil:
		const ethernetHeaderLength = 14
		viewHexadecimalDump(table, 0, "Ethernet", h.EthernetFrame.Bytes()[0:ethernetHeaderLength])
	}

	// L3
	loopForL3View := 1
	switch {
	case h.ARP != nil:
		loopForL3View = viewHexadecimalDump(table, loopForL3View, "ARP", h.ARP.Bytes())
	case h.IPv4 != nil:
		loopForL3View = viewHexadecimalDump(table, loopForL3View, "IPv4", h.IPv4.Bytes()[0:h.IPv4.Ihl*4])
	case h.IPv6 != nil:
		loopForL3View = viewHexadecimalDump(table, loopForL3View, "IPv6", h.IPv6.Bytes()[:40]) // TODO: ヘッダ長は、IPv6 のフィールドからとれるかも
	}

	// L4
	const udpHeaderLength = 8
	loopForL4View := 1 + loopForL3View
	switch {
	case h.ICMP != nil:
		loopForL4View = viewHexadecimalDump(table, loopForL4View, "ICMP", h.ICMP.Bytes())
	case h.TCP != nil:
		loopForL4View = viewHexadecimalDump(table, loopForL4View, "TCP", h.TCP.Bytes()[0:h.TCP.HeaderLength/4])
	case h.UDP != nil:
		loopForL4View = viewHexadecimalDump(table, loopForL4View, "UDP", h.UDP.Bytes()[0:udpHeaderLength])
	}

	// L5~6
	loopForL5_6View := 1 + loopForL4View
	switch {
	case h.TLSClientHello != nil:
		loopForL5_6View = viewHexadecimalDump(table, loopForL5_6View, "TLSv1.2", h.TLSClientHello.Bytes())
	case h.TLSServerHello != nil:
		loopForL5_6View = viewHexadecimalDump(table, loopForL5_6View, "TLSv1.2", h.TLSServerHello.Bytes())
	case h.TLSServerHelloFor1_3 != nil:
		loopForL5_6View = viewHexadecimalDump(table, loopForL5_6View, "TLSv1.3", h.TLSServerHelloFor1_3.Bytes())
	case h.TLSClientKeyExchange != nil:
		loopForL5_6View = viewHexadecimalDump(table, loopForL5_6View, "TLSv1.2", h.TLSClientKeyExchange.Bytes())
	case h.TLSChangeCipherSpecAndEncryptedHandshakeMessage != nil:
		loopForL5_6View = viewHexadecimalDump(table, loopForL5_6View, "TLSv1.2", h.TLSChangeCipherSpecAndEncryptedHandshakeMessage.Bytes())
	case h.TLSApplicationData != nil:
		loopForL5_6View = viewHexadecimalDump(table, loopForL5_6View, "TLSv1.2", h.TLSApplicationData.Bytes())
	case h.TLSEncryptedAlert != nil:
		loopForL5_6View = viewHexadecimalDump(table, loopForL5_6View, "TLSv1.2", h.TLSEncryptedAlert.Bytes())
	}

	// L7
	// loopForL7View := 1 + loopForL4View
	loopForL7View := 1 + loopForL5_6View
	switch {
	case h.DNS != nil:
		if h.UDP != nil {
			// まだ DNS レスポンスのパースが完璧でないので、以下のように今ある分だけ max length とするようにしてる
			dnsLength := int(h.UDP.Length - udpHeaderLength)
			if len(h.DNS.Bytes()) < int(dnsLength) {
				dnsLength = len(h.DNS.Bytes())
			}
			viewHexadecimalDump(table, loopForL7View, "DNS", h.DNS.Bytes()[0:dnsLength])
		}
		if h.TCP != nil {
			table.SetCell(loopForL7View, 0, tview.NewTableCell(padding("DNS")))
			// TODO:
		}
	case h.HTTP != nil:
		viewHexadecimalDump(table, loopForL7View, "HTTP", h.HTTP.Bytes())
	case h.HTTPResponse != nil:
		viewHexadecimalDump(table, loopForL7View, "HTTP", h.HTTPResponse.Bytes())
	}

	loopForAll := 1 + loopForL7View
	viewHexadecimalDump(table, loopForAll, "ALL", h.EthernetFrame.Bytes())

	return table
}

const maxLengthBytesOfRow = 16

func viewHexadecimalDump(table *tview.Table, viewPosition int, title string, data []byte) (nextViewPosition int) {
	table.SetCell(viewPosition, 0, tview.NewTableCell(padding(title)))

	for i := 0; ; i += maxLengthBytesOfRow {
		if len(data) < i+maxLengthBytesOfRow {
			table.SetCell(viewPosition, 1, tview.NewTableCell(padding(spacer(data[i:]))))
			break
		}
		table.SetCell(viewPosition, 1, tview.NewTableCell(padding(spacer(data[i:i+maxLengthBytesOfRow]))))

		viewPosition++
	}

	nextViewPosition = viewPosition
	return
}
