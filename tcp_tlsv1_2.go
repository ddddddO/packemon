package packemon

const IP_PAYLOAD_MAX_LENGTH = 1500 - 14 // =1486byte(IPヘッダ含む。14byteはEthernetヘッダ分)

func SendTLSClientHello(nw *NetworkInterface, clientHello *TLSClientHello, srcPort, dstPort uint16, srcIPAddr uint32, dstIPAddr uint32, firsthopMACAddr [6]byte, prevSequence uint32, prevAcknowledgment uint32) error {
	tcp := NewTCPWithData(srcPort, dstPort, clientHello.Bytes(), prevSequence, prevAcknowledgment)
	ipv4 := NewIPv4(IPv4_PROTO_TCP, srcIPAddr, dstIPAddr)
	tcp.CalculateChecksum(ipv4)

	ipv4.Data = tcp.Bytes()
	ipv4.CalculateTotalLength()
	ipv4.CalculateChecksum()

	dstMACAddr := HardwareAddr(firsthopMACAddr)
	srcMACAddr := HardwareAddr(nw.Intf.HardwareAddr)
	ethernetFrame := NewEthernetFrame(dstMACAddr, srcMACAddr, ETHER_TYPE_IPv4, ipv4.Bytes())
	return nw.Send(ethernetFrame)
}

func SendTLSClientHelloForIPv6(nw *NetworkInterface, clientHello *TLSClientHello, srcPort, dstPort uint16, srcIPAddr []uint8, dstIPAddr []uint8, firsthopMACAddr [6]byte, prevSequence uint32, prevAcknowledgment uint32) error {
	tcp := NewTCPWithData(srcPort, dstPort, clientHello.Bytes(), prevSequence, prevAcknowledgment)
	ipv6 := NewIPv6(IPv4_PROTO_TCP, srcIPAddr, dstIPAddr)
	tcp.CalculateChecksumForIPv6(ipv6)

	ipv6.Data = tcp.Bytes()
	ipv6.PayloadLength = uint16(len(ipv6.Data))

	dstMACAddr := HardwareAddr(firsthopMACAddr)
	srcMACAddr := HardwareAddr(nw.Intf.HardwareAddr)
	ethernetFrame := NewEthernetFrame(dstMACAddr, srcMACAddr, ETHER_TYPE_IPv6, ipv6.Bytes())
	return nw.Send(ethernetFrame)
}
