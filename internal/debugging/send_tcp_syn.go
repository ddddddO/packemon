package debugging

import p "github.com/ddddddO/packemon"

func (dnw *debugNetworkInterface) SendTCPsyn(firsthopMACAddr [6]byte) error {
	var srcPort uint16 = 0x9e97
	var dstPort uint16 = 0x0050       // 80
	var srcIPAddr uint32 = 0xac184fcf // 172.23.242.78
	var dstIPAddr uint32 = 0xc0a80a6e // raspberry pi
	ipv4 := p.NewIPv4(p.IPv4_PROTO_TCP, srcIPAddr, dstIPAddr)
	tcp := p.NewTCPSyn(srcPort, dstPort)
	tcp.CalculateChecksum(ipv4)

	ipv4.Data = tcp.Bytes()
	ipv4.CalculateTotalLength()
	ipv4.CalculateChecksum()

	dst := p.HardwareAddr(firsthopMACAddr)
	src := p.HardwareAddr(dnw.Intf.HardwareAddr)
	ethernetFrame := p.NewEthernetFrame(dst, src, p.ETHER_TYPE_IPv4, ipv4.Bytes())
	return dnw.Send(ethernetFrame)
}
