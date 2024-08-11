package debugging

import p "github.com/ddddddO/packemon"

func (dnw *debugNetworkInterface) SendARPrequest() error {
	arp := p.NewARPRequest(p.HardwareAddr(dnw.Intf.HardwareAddr), 0xac184fcf, [6]uint8{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, 0xac17f001)
	dst := p.HardwareAddr([6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	src := p.HardwareAddr(dnw.Intf.HardwareAddr)
	ethernetFrame := p.NewEthernetFrame(dst, src, p.ETHER_TYPE_ARP, arp.Bytes())
	return dnw.Send(ethernetFrame)
}
