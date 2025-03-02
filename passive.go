package packemon

type Passive struct {
	HTTPRes                                         *HTTPResponse
	HTTP                                            *HTTP
	TLSClientHello                                  *TLSClientHello
	TLSServerHello                                  *TLSServerHello
	TLSServerHelloFor1_3                            *TLSServerHelloFor1_3 // TODO: まとめたい
	TLSClientKeyExchange                            *TLSClientKeyExchange
	TLSChangeCipherSpecAndEncryptedHandshakeMessage *TLSChangeCipherSpecAndEncryptedHandshakeMessage
	TLSApplicationData                              *TLSApplicationData
	TLSEncryptedAlert                               *TLSEncryptedAlert
	DNS                                             *DNS
	TCP                                             *TCP
	UDP                                             *UDP
	ICMP                                            *ICMP
	IPv4                                            *IPv4
	IPv6                                            *IPv6
	ARP                                             *ARP
	EthernetFrame                                   *EthernetFrame
}

func (p *Passive) HighLayerProto() string {
	proto := "unknown"
	if p.EthernetFrame != nil {
		proto = "ETHER"
	}
	if p.ARP != nil {
		proto = "ARP"
	}
	if p.IPv4 != nil {
		proto = "IPv4"
	}
	if p.IPv6 != nil {
		proto = "IPv6"
	}
	if p.ICMP != nil {
		proto = "ICMP"
	}
	if p.UDP != nil {
		proto = "UDP"
	}
	if p.TCP != nil {
		proto = "TCP"
	}
	// TODO: ちょっとTLSのversionは出さないとかにした方がいいかも？
	if p.TLSClientHello != nil || p.TLSServerHello != nil || p.TLSClientKeyExchange != nil || p.TLSChangeCipherSpecAndEncryptedHandshakeMessage != nil || p.TLSApplicationData != nil || p.TLSEncryptedAlert != nil {
		proto = "TLSv1.2"
	}
	if p.TLSServerHelloFor1_3 != nil {
		proto = "TLSv1.3"
	}
	if p.DNS != nil {
		proto = "DNS"
	}
	if p.HTTP != nil || p.HTTPRes != nil {
		proto = "HTTP"
	}

	return proto
}
