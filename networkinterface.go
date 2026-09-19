package packemon

import (
	"context"
	"encoding/binary"
)

// net.Interfaces と pcap.FindAllDevs で取れる情報. Windows だとNameが違う
type InterfaceDevice struct {
	InterfaceName string
	DeviceName    string
	Description   string
	MacAddr       string
	IPAddrs       []string
}

type InterfaceDevices []*InterfaceDevice

func NewNetworkInterface(nwInterface string) (*NetworkInterface, error) {
	return newNetworkInterface(nwInterface)
}

func (nw *NetworkInterface) Send(ethernetFrame *EthernetFrame) error {
	return nw.send(ethernetFrame)
}

func (nw *NetworkInterface) Recieve(ctx context.Context, shouldParseFull bool) error {
	return nw.recieve(ctx, shouldParseFull)
}

func (nw *NetworkInterface) Close() error {
	return nw.close()
}

// TODO: 一時的なもの。TLS1.3 を試すための
const DEBUG_10443 uint16 = 0x28CB

// ParsedPacket は、受信した生バイト列をスクラッチ実装でパースして Passive を返す。
// 上位層のパースに失敗（panic）しても、そこまでにパースできた層の Passive を返す（fail-soft）。
// L5 以上（DNS/HTTP/TLS 等）のパースは shouldParseFull が true のときのみ行う。
func ParsedPacket(recieved []byte, shouldParseFull bool) (passive *Passive) {
	ethernetFrame := ParsedEthernetFrame(recieved)
	passive = &Passive{
		EthernetFrame: ethernetFrame,
	}
	defer func() {
		if e := recover(); e != nil {
		}
	}()

	// IEEE802.1Q(VLANタグ)付きは、タグ内の EtherType で上位プロトコルを判定する
	etherType := ethernetFrame.Header.Typ
	if etherType == ETHER_TYPE_DOT1Q && ethernetFrame.Header.Dot1QFiels != nil {
		etherType = ethernetFrame.Header.Dot1QFiels.Type
	}

	switch etherType {
	case ETHER_TYPE_ARP:
		passive.ARP = ParsedARP(ethernetFrame.Data)
		return passive
	case ETHER_TYPE_IPv4:
		return parsedPassiveIPv4(ethernetFrame, shouldParseFull)
	case ETHER_TYPE_IPv6:
		return parsedPassiveIPv6(ethernetFrame, shouldParseFull)
	default:
		return passive
	}
}

// parsedPassiveIPv4 は IPv4 とその上位層をパースする。
// 上位層で panic しても、そこまでの Passive を返す（fail-soft）。
func parsedPassiveIPv4(ethernetFrame *EthernetFrame, shouldParseFull bool) (passive *Passive) {
	ipv4 := ParsedIPv4(ethernetFrame.Data)
	passive = &Passive{
		EthernetFrame: ethernetFrame,
		IPv4:          ipv4,
	}
	defer func() {
		if e := recover(); e != nil {
		}
	}()

	switch ipv4.Protocol {
	case IPv4_PROTO_ICMPv4:
		passive.ICMPv4 = ParsedICMPv4(ipv4.Data)
	case IPv4_PROTO_TCP:
		parsedPassiveTCPLayer(passive, ipv4.Data, shouldParseFull)
	case IPv4_PROTO_UDP:
		parsedPassiveUDPLayer(passive, ipv4.Data, shouldParseFull)
	}
	return passive
}

// parsedPassiveIPv6 は IPv6 とその上位層をパースする。
// 上位層で panic しても、そこまでの Passive を返す（fail-soft）。
func parsedPassiveIPv6(ethernetFrame *EthernetFrame, shouldParseFull bool) (passive *Passive) {
	ipv6 := ParsedIPv6(ethernetFrame.Data)
	passive = &Passive{
		EthernetFrame: ethernetFrame,
		IPv6:          ipv6,
	}
	defer func() {
		if e := recover(); e != nil {
		}
	}()

	switch ipv6.NextHeader {
	case IPv6_NEXT_HEADER_ICMPv6:
		// TODO: ICMPv6 のパース
	case IPv6_NEXT_HEADER_TCP:
		parsedPassiveTCPLayer(passive, ipv6.Data, shouldParseFull)
	case IPv6_NEXT_HEADER_UDP:
		parsedPassiveUDPLayer(passive, ipv6.Data, shouldParseFull)
	}
	return passive
}

// parsedPassiveTCPLayer は TCP と、well-known port から判定できる上位層（HTTP/TLS）を
// パースして passive へ書き足す。IPv4/IPv6 の両方から使う。
func parsedPassiveTCPLayer(passive *Passive, payload []byte, shouldParseFull bool) {
	tcp := ParsedTCP(payload)
	passive.TCP = tcp

	if !shouldParseFull {
		return
	}

	switch tcp.DstPort {
	case PORT_HTTP:
		if tcp.Flags == TCP_FLAGS_PSH_ACK {
			if http := ParsedHTTPRequest(tcp.Data); http != nil {
				passive.HTTP = http
			}
		}
		return
	case PORT_HTTPS, DEBUG_10443:
		ParsedTLSToPassive(tcp, passive)
		return
	}

	switch tcp.SrcPort {
	case PORT_HTTP:
		if tcp.Flags == TCP_FLAGS_FIN_PSH_ACK || tcp.Flags == TCP_FLAGS_PSH_ACK {
			if httpRes := ParsedHTTPResponse(tcp.Data); httpRes != nil {
				passive.HTTPRes = httpRes
			}
		}
		return
	case PORT_HTTPS, DEBUG_10443:
		ParsedTLSToPassive(tcp, passive)
		return
	}
}

// parsedPassiveUDPLayer は UDP と、well-known port から判定できる上位層（DNS）を
// パースして passive へ書き足す。IPv4/IPv6 の両方から使う。
func parsedPassiveUDPLayer(passive *Passive, payload []byte, shouldParseFull bool) {
	udp := ParsedUDP(payload)
	passive.UDP = udp

	if !shouldParseFull {
		return
	}

	// DNS以外は一旦udpまでのみviewする
	if udp.DstPort != PORT_DNS && udp.SrcPort != PORT_DNS {
		return
	}

	// TODO: 53確かtcpもあったからそれのハンドリング考慮するいつか
	flags := binary.BigEndian.Uint16(udp.Data[2:4])
	if udp.DstPort == PORT_DNS && IsDNSRequest(flags) {
		passive.DNS = ParsedDNSRequest(udp.Data)
		return
	}
	if udp.SrcPort == PORT_DNS && IsDNSResponse(flags) {
		passive.DNS = ParsedDNSResponse(udp.Data)
	}
}
