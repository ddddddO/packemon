package debugging

import (
	"bytes"
	"encoding/binary"

	p "github.com/ddddddO/packemon"
)

type debugNetworkInterface struct {
	*p.NetworkInterface
}

func NewDebugNetworkInterface(netIF *p.NetworkInterface) *debugNetworkInterface {
	return &debugNetworkInterface{
		NetworkInterface: netIF,
	}
}

func (dnw *debugNetworkInterface) SendARPrequest(firsthopMACAddr [6]byte) error {
	arp := p.NewARP()
	dst := p.HardwareAddr(firsthopMACAddr)
	src := p.HardwareAddr(dnw.Intf.HardwareAddr)
	ethernetFrame := p.NewEthernetFrame(dst, src, p.ETHER_TYPE_ARP, arp.Bytes())
	return dnw.Send(ethernetFrame)
}

func (dnw *debugNetworkInterface) SendICMPechoRequest(firsthopMACAddr [6]byte) error {
	icmp := p.NewICMP()
	ipv4 := p.NewIPv4(p.IPv4_PROTO_ICMP, 0xa32b661d) // dst: 163.43.102.29 = tools.m-bsys.com
	ipv4.Data = icmp.Bytes()
	ipv4.CalculateTotalLength()
	ipv4.CalculateChecksum()
	dst := p.HardwareAddr(firsthopMACAddr)
	src := p.HardwareAddr(dnw.Intf.HardwareAddr)
	ethernetFrame := p.NewEthernetFrame(dst, src, p.ETHER_TYPE_IPv4, ipv4.Bytes())
	return dnw.Send(ethernetFrame)
}

func (dnw *debugNetworkInterface) SendDNSquery(firsthopMACAddr [6]byte) error {
	dns := &p.DNS{
		TransactionID: 0x1234,
		Flags:         0x0100, // standard query
		Questions:     0x0001,
		AnswerRRs:     0x0000,
		AuthorityRRs:  0x0000,
		AdditionalRRs: 0x0000,
		Queries: &p.Queries{
			Typ:   0x0001, // A
			Class: 0x0001, // IN
		},
	}
	// dns.domain("github.com")
	dns.Domain("go.dev")
	udp := &p.UDP{
		SrcPort:  0x0401, // 1025
		DstPort:  0x0035, // 53
		Length:   0x0000,
		Checksum: 0x0000,
	}
	udp.Data = dns.Bytes()
	udp.Len()
	ipv4 := p.NewIPv4(p.IPv4_PROTO_UDP, 0x08080808) // 8.8.8.8 = DNSクエリ用
	ipv4.Data = udp.Bytes()
	ipv4.CalculateTotalLength()
	ipv4.CalculateChecksum()
	dst := p.HardwareAddr(firsthopMACAddr)
	src := p.HardwareAddr(dnw.Intf.HardwareAddr)
	ethernetFrame := p.NewEthernetFrame(dst, src, p.ETHER_TYPE_IPv4, ipv4.Bytes())
	return dnw.Send(ethernetFrame)
}

func (dnw *debugNetworkInterface) SendTCPsyn(firsthopMACAddr [6]byte) error {
	tcp := p.NewTCPSyn()
	ipv4 := p.NewIPv4(p.IPv4_PROTO_TCP, 0xa32b661d) // 163.43.102.29 = tools.m-bsys.com こちらで、ack返ってきた
	// https://atmarkit.itmedia.co.jp/ait/articles/0401/29/news080_2.html
	// 「「チェックサム」フィールド：16bit幅」
	tcp.Checksum = func() uint16 {
		pseudoTCPHeader := func() []byte {
			var buf bytes.Buffer
			b := make([]byte, 4)
			binary.BigEndian.PutUint32(b, ipv4.SrcAddr)
			buf.Write(b)
			b = make([]byte, 4)
			binary.BigEndian.PutUint32(b, ipv4.DstAddr)
			buf.Write(b)
			padding := byte(0x00)
			buf.WriteByte(padding)
			buf.WriteByte(ipv4.Protocol)
			b = make([]byte, 2)
			binary.BigEndian.PutUint16(b, uint16(len(tcp.Bytes())))
			buf.Write(b)
			return buf.Bytes()
		}()
		var forTCPChecksum bytes.Buffer
		forTCPChecksum.Write(pseudoTCPHeader)
		forTCPChecksum.Write(tcp.Bytes())
		return binary.BigEndian.Uint16(tcp.CheckSum(forTCPChecksum.Bytes()))
	}()
	ipv4.Data = tcp.Bytes()
	ipv4.CalculateTotalLength()
	ipv4.CalculateChecksum()
	dst := p.HardwareAddr(firsthopMACAddr)
	src := p.HardwareAddr(dnw.Intf.HardwareAddr)
	ethernetFrame := p.NewEthernetFrame(dst, src, p.ETHER_TYPE_IPv4, ipv4.Bytes())
	return dnw.Send(ethernetFrame)
}

func (dnw *debugNetworkInterface) SendHTTPget(firsthopMACAddr [6]byte) error {
	http := p.NewHTTP()
	tcp := p.NewTCPWithData(http.Bytes())
	ipv4 := p.NewIPv4(p.IPv4_PROTO_TCP, 0x88bb0609) // 136.187.6.9 = research.nii.ac.jp
	// https://atmarkit.itmedia.co.jp/ait/articles/0401/29/news080_2.html
	// 「「チェックサム」フィールド：16bit幅」
	tcp.Checksum = func() uint16 {
		pseudoTCPHeader := func() []byte {
			var buf bytes.Buffer
			b := make([]byte, 4)
			binary.BigEndian.PutUint32(b, ipv4.SrcAddr)
			buf.Write(b)
			b = make([]byte, 4)
			binary.BigEndian.PutUint32(b, ipv4.DstAddr)
			buf.Write(b)
			padding := byte(0x00)
			buf.WriteByte(padding)
			buf.WriteByte(ipv4.Protocol)
			b = make([]byte, 2)
			binary.BigEndian.PutUint16(b, uint16(len(tcp.Bytes())))
			buf.Write(b)
			return buf.Bytes()
		}()
		var forTCPChecksum bytes.Buffer
		forTCPChecksum.Write(pseudoTCPHeader)
		forTCPChecksum.Write(tcp.Bytes())
		return binary.BigEndian.Uint16(tcp.CheckSum(forTCPChecksum.Bytes()))
	}()
	ipv4.Data = tcp.Bytes()
	ipv4.CalculateTotalLength()
	ipv4.CalculateChecksum()
	dst := p.HardwareAddr(firsthopMACAddr)
	src := p.HardwareAddr(dnw.Intf.HardwareAddr)
	ethernetFrame := p.NewEthernetFrame(dst, src, p.ETHER_TYPE_IPv4, ipv4.Bytes())
	return dnw.Send(ethernetFrame)
}
