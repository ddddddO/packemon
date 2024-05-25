package packemon

type Passive struct {
	HTTPRes       *HTTPResponse
	HTTP          *HTTP
	DNS           *DNS
	TCP           *TCP
	UDP           *UDP
	ICMP          *ICMP
	ARP           *ARP
	IPv4          *IPv4
	EthernetFrame *EthernetFrame
}

func (p *Passive) HighLayerProto() string {
	proto := "unkown"
	if p.EthernetFrame != nil {
		proto = "Ethernet"
	}
	if p.IPv4 != nil {
		proto = "IPv4"
	}
	if p.ARP != nil {
		proto = "ARP"
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
