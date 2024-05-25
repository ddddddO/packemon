package packemon

type Passive struct {
	HTTPRes       *HTTPResponse
	HTTP          *HTTP
	DNS           *DNS
	TCP           *TCP
	UDP           *UDP
	ICMP          *ICMP
	IPv4          *IPv4
	ARP           *ARP
	EthernetFrame *EthernetFrame
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
	if p.ICMP != nil {
		proto = "ICMP"
	}
	if p.UDP != nil {
		proto = "UDP"
	}
	if p.TCP != nil {
		proto = "TCP"
	}
	if p.DNS != nil {
		proto = "DNS"
	}
	if p.HTTP != nil || p.HTTPRes != nil {
		proto = "HTTP"
	}

	return proto
}
