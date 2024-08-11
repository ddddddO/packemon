package debugging

import p "github.com/ddddddO/packemon"

func (dnw *debugNetworkInterface) SendICMPechoRequest(firsthopMACAddr [6]byte) error {
	icmp := p.NewICMP()
	var srcIPAddr uint32 = 0xac184fcf // 172.23.242.78
	var dstIPAddr uint32 = 0xc0a80a6e // raspberry pi
	ipv4 := p.NewIPv4(p.IPv4_PROTO_ICMP, srcIPAddr, dstIPAddr)
	ipv4.Data = icmp.Bytes()
	ipv4.CalculateTotalLength()
	ipv4.CalculateChecksum()
	dst := p.HardwareAddr(firsthopMACAddr)
	src := p.HardwareAddr(dnw.Intf.HardwareAddr)
	ethernetFrame := p.NewEthernetFrame(dst, src, p.ETHER_TYPE_IPv4, ipv4.Bytes())
	return dnw.Send(ethernetFrame)
}
