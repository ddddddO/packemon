package monitor

import (
	"github.com/ddddddO/packemon"
	"github.com/ddddddO/packemon/internal/tui"
	"github.com/rivo/tview"
)

type HexadecimalDump struct {
	*packemon.EthernetFrame
	*packemon.ARP
	*packemon.IPv4
	*packemon.IPv6

	*packemon.ICMPv4Echo
	*packemon.ICMPv4Error
	*packemon.ICMPv4ParameterProblem
	*packemon.ICMPv4Redirect

	*packemon.ICMPv6Error
	*packemon.ICMPv6PacketTooBig
	*packemon.ICMPv6ParameterProblem
	*packemon.ICMPv6Echo
	*packemon.ICMPv6NeighborDiscovery
	*packemon.ICMPv6RouterAdvertisement
	*packemon.ICMPv6MulticastListenerDiscovery

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

func (h *HexadecimalDump) viewTable() *tview.Table {
	table := tview.NewTable().SetBorders(false)
	table.Box = tview.NewBox().SetBorder(true).SetTitle(" Hexadecimal dump ").SetTitleAlign(tview.AlignLeft).SetBorderPadding(1, 1, 1, 1)

	// L2
	loopForL2View := 0
	switch {
	case h.EthernetFrame != nil:
		frame := h.EthernetFrame.Bytes()
		ethernetHeaderLength := 14
		if h.EthernetFrame.Header.Typ == packemon.ETHER_TYPE_DOT1Q && len(frame) >= 18 {
			ethernetHeaderLength = 18
			loopForL2View++
		}
		viewHexadecimalDump(table, 0, "Ethernet", frame[0:ethernetHeaderLength])
	}

	// L3
	loopForL3View := 1 + loopForL2View
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
	case h.ICMPv4Echo != nil:
		switch h.ICMPv4Echo.Header.Typ {
		case packemon.ICMPv4_TYPE_ECHO:
			loopForL4View = viewHexadecimalDump(table, loopForL4View, "ICMPv4 Echo", h.ICMPv4Echo.Bytes())
		case packemon.ICMPv4_TYPE_ECHO_REPLY:
			loopForL4View = viewHexadecimalDump(table, loopForL4View, "ICMPv4 Echo Reply", h.ICMPv4Echo.Bytes())
		case packemon.ICMPv4_TYPE_TIMESTAMP:
			loopForL4View = viewHexadecimalDump(table, loopForL4View, "ICMPv4 Timestamp", h.ICMPv4Echo.Bytes())
		case packemon.ICMPv4_TYPE_TIMESTAMP_REPLY:
			loopForL4View = viewHexadecimalDump(table, loopForL4View, "ICMPv4 Timestamp Reply", h.ICMPv4Echo.Bytes())
		case packemon.ICMPv4_TYPE_INFORMATION_REQUEST:
			loopForL4View = viewHexadecimalDump(table, loopForL4View, "ICMPv4 Information Request", h.ICMPv4Echo.Bytes())
		case packemon.ICMPv4_TYPE_INFORMATION_REPLY:
			loopForL4View = viewHexadecimalDump(table, loopForL4View, "ICMPv4 Information Reply", h.ICMPv4Echo.Bytes())
		case packemon.ICMPv4_TYPE_ADDRESS_MASK_REQUEST:
			loopForL4View = viewHexadecimalDump(table, loopForL4View, "ICMPv4 Address Mask Request", h.ICMPv4Echo.Bytes())
		case packemon.ICMPv4_TYPE_ADDRESS_MASK_REPLY:
			loopForL4View = viewHexadecimalDump(table, loopForL4View, "ICMPv4 Address Mask Reply", h.ICMPv4Echo.Bytes())
		default:
			// 定義なし。なんらかのICMPの正常系通知だけど多分変なパケットの時
			loopForL4View = viewHexadecimalDump(table, loopForL4View, "ICMPv4 Something Echo", h.ICMPv4Echo.Bytes())
		}
	case h.ICMPv4Error != nil:
		switch h.ICMPv4Error.Header.Typ {
		case packemon.ICMPv4_TYPE_DESTINATION_UNREACHABLE:
			loopForL4View = viewHexadecimalDump(table, loopForL4View, "ICMPv4 Destination Unreachable", h.ICMPv4Error.Bytes())
		case packemon.ICMPv4_TYPE_TIME_EXCEEDED:
			loopForL4View = viewHexadecimalDump(table, loopForL4View, "ICMPv4 Time Exceeded", h.ICMPv4Error.Bytes())
		case packemon.ICMPv4_TYPE_SOURCE_QUENCH:
			loopForL4View = viewHexadecimalDump(table, loopForL4View, "ICMPv4 Source Quench", h.ICMPv4Error.Bytes())
		default:
			// 定義なし。なんらかのICMPのエラーだけど多分変なパケットの時
			loopForL4View = viewHexadecimalDump(table, loopForL4View, "ICMPv4 Something Error", h.ICMPv4Error.Bytes())
		}
	case h.ICMPv4ParameterProblem != nil:
		switch h.ICMPv4ParameterProblem.Header.Typ {
		case packemon.ICMPv4_TYPE_PARAMETER_PROBLEM:
			loopForL4View = viewHexadecimalDump(table, loopForL4View, "ICMPv4 Parameter Problem", h.ICMPv4ParameterProblem.Bytes())
		default:
			// 定義なし。なんらかのICMPのエラーだけど多分変なパケットの時
			loopForL4View = viewHexadecimalDump(table, loopForL4View, "ICMPv4 Something Error", h.ICMPv4ParameterProblem.Bytes())
		}
	case h.ICMPv4Redirect != nil:
		switch h.ICMPv4Redirect.Header.Typ {
		case packemon.ICMPv4_TYPE_REDIRECT:
			loopForL4View = viewHexadecimalDump(table, loopForL4View, "ICMPv4 Redirect", h.ICMPv4Redirect.Bytes())
		default:
			// 定義なし。なんらかのICMPパケットだけど多分変なパケットの時
			loopForL4View = viewHexadecimalDump(table, loopForL4View, "ICMPv4 Something Redirect", h.ICMPv4Redirect.Bytes())
		}

	case h.ICMPv6Error != nil:
		switch h.ICMPv6Error.Header.Typ {
		case packemon.ICMPv6_TYPE_DESTINATION_UNREACHABLE:
			loopForL4View = viewHexadecimalDump(table, loopForL4View, "ICMPv6 Destination Unreachable", h.ICMPv6Error.Bytes())
		case packemon.ICMPv6_TYPE_TIME_EXCEEDED:
			loopForL4View = viewHexadecimalDump(table, loopForL4View, "ICMPv6 Time Exceeded", h.ICMPv6Error.Bytes())
		case packemon.ICMPv6_TYPE_PRIVATE_EXPERIMENTATION_100:
			loopForL4View = viewHexadecimalDump(table, loopForL4View, "ICMPv6 Private Experimentation 100", h.ICMPv6Error.Bytes())
		case packemon.ICMPv6_TYPE_PRIVATE_EXPERIMENTATION_101:
			loopForL4View = viewHexadecimalDump(table, loopForL4View, "ICMPv6 Private Experimentation 101", h.ICMPv6Error.Bytes())
		case packemon.ICMPv6_TYPE_RESERVED_FOR_EXPANSION_OF_ICMPV6_ERROR_MESSAGES:
			loopForL4View = viewHexadecimalDump(table, loopForL4View, "ICMPv6 Reserved for expansion of ICMPv6 error messages", h.ICMPv6Error.Bytes())
		default:
			// 定義なし。なんらかのICMPのエラーだけど多分変なパケットの時
			loopForL4View = viewHexadecimalDump(table, loopForL4View, "ICMPv6 Something Error", h.ICMPv6Error.Bytes())
		}
	case h.ICMPv6PacketTooBig != nil:
		switch h.ICMPv6PacketTooBig.Header.Typ {
		case packemon.ICMPv6_TYPE_PACKET_TOO_BIG:
			loopForL4View = viewHexadecimalDump(table, loopForL4View, "ICMPv6 Packet Too Big", h.ICMPv6PacketTooBig.Bytes())
		default:
			// 定義なし。なんらかのICMPのエラーだけど多分変なパケットの時
			loopForL4View = viewHexadecimalDump(table, loopForL4View, "ICMPv6 Something Error", h.ICMPv6PacketTooBig.Bytes())
		}
	case h.ICMPv6ParameterProblem != nil:
		switch h.ICMPv6ParameterProblem.Header.Typ {
		case packemon.ICMPv6_TYPE_PARAMETER_PROBLEM:
			loopForL4View = viewHexadecimalDump(table, loopForL4View, "ICMPv6 Parameter Problem", h.ICMPv6ParameterProblem.Bytes())
		default:
			// 定義なし。なんらかのICMPのエラーだけど多分変なパケットの時
			loopForL4View = viewHexadecimalDump(table, loopForL4View, "ICMPv6 Something Error", h.ICMPv6ParameterProblem.Bytes())
		}
	case h.ICMPv6Echo != nil:
		switch h.ICMPv6Echo.Header.Typ {
		case packemon.ICMPv6_TYPE_ECHO_REQUEST:
			loopForL4View = viewHexadecimalDump(table, loopForL4View, "ICMPv6 Echo Request", h.ICMPv6Echo.Bytes())
		case packemon.ICMPv6_TYPE_ECHO_REPLY:
			loopForL4View = viewHexadecimalDump(table, loopForL4View, "ICMPv6 Echo Reply", h.ICMPv6Echo.Bytes())
		case packemon.ICMPv6_TYPE_PRIVATE_EXPERIMENTATION_200:
			loopForL4View = viewHexadecimalDump(table, loopForL4View, "ICMPv6 Private Experimentation 200", h.ICMPv6Echo.Bytes())
		case packemon.ICMPv6_TYPE_PRIVATE_EXPERIMENTATION_201:
			loopForL4View = viewHexadecimalDump(table, loopForL4View, "ICMPv6 Private Experimentation 201", h.ICMPv6Echo.Bytes())
		default:
			// 定義なし。なんらかのICMPの正常系通知だけど多分変なパケットの時
			loopForL4View = viewHexadecimalDump(table, loopForL4View, "ICMPv6 Something Echo", h.ICMPv6Echo.Bytes())
		}
	case h.ICMPv6NeighborDiscovery != nil:
		switch h.ICMPv6NeighborDiscovery.Header.Typ {
		case packemon.ICMPv6_TYPE_ROUTER_SOLICITATION:
			loopForL4View = viewHexadecimalDump(table, loopForL4View, "ICMPv6 Router Solicitation", h.ICMPv6NeighborDiscovery.Bytes())
		case packemon.ICMPv6_TYPE_ROUTER_ADVERTISEMENT:
			loopForL4View = viewHexadecimalDump(table, loopForL4View, "ICMPv6 Router Advertisement", h.ICMPv6NeighborDiscovery.Bytes())
		case packemon.ICMPv6_TYPE_NEIGHBOR_SOLICITATION:
			loopForL4View = viewHexadecimalDump(table, loopForL4View, "ICMPv6 Neighbor Solicitation", h.ICMPv6NeighborDiscovery.Bytes())
		case packemon.ICMPv6_TYPE_NEIGHBOR_ADVERTISEMENT:
			loopForL4View = viewHexadecimalDump(table, loopForL4View, "ICMPv6 Neighbor Advertisement", h.ICMPv6NeighborDiscovery.Bytes())
		case packemon.ICMPv6_TYPE_REDIRECT:
			loopForL4View = viewHexadecimalDump(table, loopForL4View, "ICMPv6 Redirect", h.ICMPv6NeighborDiscovery.Bytes())
		case packemon.ICMPv6_TYPE_SECURE_NEIGHBOR_DISCOVERY_141:
			loopForL4View = viewHexadecimalDump(table, loopForL4View, "ICMPv6 Secure Neighbor Discovery 141", h.ICMPv6NeighborDiscovery.Bytes())
		case packemon.ICMPv6_TYPE_SECURE_NEIGHBOR_DISCOVERY_142:
			loopForL4View = viewHexadecimalDump(table, loopForL4View, "ICMPv6 Secure Neighbor Discovery 142", h.ICMPv6NeighborDiscovery.Bytes())
		case packemon.ICMPv6_TYPE_HOME_AGENT_DISCOVERY_144:
			loopForL4View = viewHexadecimalDump(table, loopForL4View, "ICMPv6 Home Agent Discovery 144", h.ICMPv6NeighborDiscovery.Bytes())
		case packemon.ICMPv6_TYPE_HOME_AGENT_DISCOVERY_145:
			loopForL4View = viewHexadecimalDump(table, loopForL4View, "ICMPv6 Home Agent Discovery 145", h.ICMPv6NeighborDiscovery.Bytes())
		default:
			// 定義なし。なんらかのICMPの正常系通知だけど多分変なパケットの時
			loopForL4View = viewHexadecimalDump(table, loopForL4View, "ICMPv6 Something Neighbor Discovery", h.ICMPv6NeighborDiscovery.Bytes())
		}
	case h.ICMPv6RouterAdvertisement != nil:
		loopForL4View = viewHexadecimalDump(table, loopForL4View, "ICMPv6 Router Advertisement", h.ICMPv6RouterAdvertisement.Bytes())
	case h.ICMPv6MulticastListenerDiscovery != nil:
		switch h.ICMPv6MulticastListenerDiscovery.Header.Typ {
		case packemon.ICMPv6_TYPE_MULTICAST_LISTENER_QUERY:
			loopForL4View = viewHexadecimalDump(table, loopForL4View, "ICMPv6 Multicast Listener Query", h.ICMPv6MulticastListenerDiscovery.Bytes())
		case packemon.ICMPv6_TYPE_MULTICAST_LISTENER_REPORT:
			loopForL4View = viewHexadecimalDump(table, loopForL4View, "ICMPv6 Multicast Listener Report", h.ICMPv6MulticastListenerDiscovery.Bytes())
		case packemon.ICMPv6_TYPE_MULTICAST_LISTENER_DONE:
			loopForL4View = viewHexadecimalDump(table, loopForL4View, "ICMPv6 Multicast Listener Done", h.ICMPv6MulticastListenerDiscovery.Bytes())
		case packemon.ICMPv6_TYPE_MLDv2_MULTICAST_LISTENER_REPORT:
			loopForL4View = viewHexadecimalDump(table, loopForL4View, "ICMPv6 MLDv2 Multicast Listener Report", h.ICMPv6MulticastListenerDiscovery.Bytes())
		default:
			// 定義なし。なんらかのICMPの正常系通知だけど多分変なパケットの時
			loopForL4View = viewHexadecimalDump(table, loopForL4View, "ICMPv6 Something Multicast Listener Discovery", h.ICMPv6MulticastListenerDiscovery.Bytes())
		}

	case h.TCP != nil:
		loopForL4View = viewHexadecimalDump(table, loopForL4View, "TCP", h.TCP.Bytes()[0:h.TCP.HeaderLength/4])
	case h.UDP != nil:
		loopForL4View = viewHexadecimalDump(table, loopForL4View, "UDP", h.UDP.Bytes()[0:udpHeaderLength])
	}

	// L5~6
	loopForL5_6View := 1 + loopForL4View
	switch {
	case h.TLSClientHello != nil:
		loopForL5_6View = viewHexadecimalDump(table, loopForL5_6View, "TLS", h.TLSClientHello.Bytes())
	case h.TLSServerHello != nil:
		loopForL5_6View = viewHexadecimalDump(table, loopForL5_6View, "TLS", h.TLSServerHello.Bytes())
	case h.TLSServerHelloFor1_3 != nil:
		loopForL5_6View = viewHexadecimalDump(table, loopForL5_6View, "TLS", h.TLSServerHelloFor1_3.Bytes())
	case h.TLSClientKeyExchange != nil:
		loopForL5_6View = viewHexadecimalDump(table, loopForL5_6View, "TLS", h.TLSClientKeyExchange.Bytes())
	case h.TLSChangeCipherSpecAndEncryptedHandshakeMessage != nil:
		loopForL5_6View = viewHexadecimalDump(table, loopForL5_6View, "TLS", h.TLSChangeCipherSpecAndEncryptedHandshakeMessage.Bytes())
	case h.TLSApplicationData != nil:
		loopForL5_6View = viewHexadecimalDump(table, loopForL5_6View, "TLS", h.TLSApplicationData.Bytes())
	case h.TLSEncryptedAlert != nil:
		loopForL5_6View = viewHexadecimalDump(table, loopForL5_6View, "TLS", h.TLSEncryptedAlert.Bytes())
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
			table.SetCell(loopForL7View, 0, tview.NewTableCell(tui.Padding("DNS")))
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
	table.SetCell(viewPosition, 0, tview.NewTableCell(tui.Padding(title)))

	for i := 0; ; i += maxLengthBytesOfRow {
		if len(data) < i+maxLengthBytesOfRow {
			table.SetCell(viewPosition, 1, tview.NewTableCell(tui.Padding(tui.Spacer(data[i:]))))
			break
		}
		table.SetCell(viewPosition, 1, tview.NewTableCell(tui.Padding(tui.Spacer(data[i:i+maxLengthBytesOfRow]))))

		viewPosition++
	}

	nextViewPosition = viewPosition
	return
}
