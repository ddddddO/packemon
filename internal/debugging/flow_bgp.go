package debugging

import (
	"bytes"
	"log"

	p "github.com/ddddddO/packemon"
	"golang.org/x/sys/unix"
)

const BGP_PORT = 0x00b3 // 179

func (dnw *debugNetworkInterface) FlowBGP() error {
	var srcPort uint16 = 0xa330
	var dstPort uint16 = BGP_PORT
	var srcIPAddr uint32 = 0xac110004                                         // 172.17.0.4
	var dstIPAddr uint32 = 0xac110005                                         // 172.17.0.5
	srcMACAddr := p.HardwareAddr(dnw.Intf.HardwareAddr)                       // BGPRouter1
	dstMACAddr := p.HardwareAddr([6]byte{0xd2, 0xd2, 0x41, 0x7c, 0x25, 0xcb}) // BGPRouter2

	// SYN
	tcp := p.NewTCPSyn(srcPort, dstPort)
	ipv4 := p.NewIPv4(p.IPv4_PROTO_TCP, srcIPAddr, dstIPAddr)
	tcp.CalculateChecksum(ipv4)
	ipv4.Data = tcp.Bytes()
	ipv4.CalculateTotalLength()
	ipv4.CalculateChecksum()
	ethernetFrame := p.NewEthernetFrame(dstMACAddr, srcMACAddr, p.ETHER_TYPE_IPv4, ipv4.Bytes())
	if err := dnw.Send(ethernetFrame); err != nil {
		return err
	}

	for {
		recieved := make([]byte, 1500)
		n, _, err := unix.Recvfrom(dnw.Socket, recieved, 0)
		if err != nil {
			if n == -1 {
				continue
			}
			return err
		}

		ethernetFrame := p.ParsedEthernetFrame(recieved)

		switch ethernetFrame.Header.Typ {
		case p.ETHER_TYPE_IPv4:
			ipv4 := p.ParsedIPv4(ethernetFrame.Data)

			switch ipv4.Protocol {
			case p.IPv4_PROTO_TCP:
				tcp := p.ParsedTCP(ipv4.Data)

				switch tcp.DstPort {
				case srcPort: // synパケットの送信元ポート
					if tcp.Flags == p.TCP_FLAGS_SYN_ACK {
						log.Println("passive TCP_FLAGS_SYN_ACK")

						// syn/ackを受け取ったのでack送信
						tcp := p.NewTCPAck(srcPort, dstPort, tcp.Sequence, tcp.Acknowledgment)
						ipv4 := p.NewIPv4(p.IPv4_PROTO_TCP, srcIPAddr, dstIPAddr)
						tcp.CalculateChecksum(ipv4)
						ipv4.Data = tcp.Bytes()
						ipv4.CalculateTotalLength()
						ipv4.CalculateChecksum()
						ethernetFrame := p.NewEthernetFrame(dstMACAddr, srcMACAddr, p.ETHER_TYPE_IPv4, ipv4.Bytes())
						if err := dnw.Send(ethernetFrame); err != nil {
							return err
						}

						// ここで BGP open を送る
						if err := dnw.BGPOpen(srcPort, dstPort, srcIPAddr, dstIPAddr, dstMACAddr, tcp.Sequence, tcp.Acknowledgment); err != nil {
							return err
						}
						continue
					}

					if tcp.Flags == p.TCP_FLAGS_ACK {
						log.Println("passive TCP_FLAGS_ACK")
						continue
					}

					if tcp.Flags == p.TCP_FLAGS_PSH_ACK {
						log.Println("passive TCP_FLAGS_PSH_ACK")

						// ここで対向から BGP の OPEN / KEEPALIVE / UPDATE が取れるはず
						continue
					}
				}
			}
		}
	}

	return nil
}

func (dnw *debugNetworkInterface) BGPOpen(srcPort, dstPort uint16, srcIPAddr uint32, dstIPAddr uint32, firsthopMACAddr [6]byte, prevSequence uint32, prevAcknowledgment uint32) error {
	bgpopen := NewBGPOpen()
	tcp := p.NewTCPWithData(srcPort, dstPort, bgpopen.Bytes(), prevSequence, prevAcknowledgment)
	ipv4 := p.NewIPv4(p.IPv4_PROTO_TCP, srcIPAddr, dstIPAddr)
	tcp.CalculateChecksum(ipv4)

	ipv4.Data = tcp.Bytes()
	ipv4.CalculateTotalLength()
	ipv4.CalculateChecksum()

	dstMACAddr := p.HardwareAddr(firsthopMACAddr)
	srcMACAddr := p.HardwareAddr(dnw.Intf.HardwareAddr)
	ethernetFrame := p.NewEthernetFrame(dstMACAddr, srcMACAddr, p.ETHER_TYPE_IPv4, ipv4.Bytes())
	return dnw.Send(ethernetFrame)
}

const BGP_TYPE_OPEN = 0x01
const BGP_VERSION = 0x04

type BGP struct {
	Marker                   []byte // 16byte
	Length                   []byte // 2byte
	Typ                      byte   // 1byte
	Version                  byte   // 1byte
	MyAS                     []byte // 2byte
	HoldTime                 []byte // 2byte
	Identifier               []byte // 4byte
	OptionalParametersLength byte   // 1byte
	OptionalParameters       []byte
}

func NewBGPOpen() *BGP {
	b := &BGP{
		Marker:                   []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		Typ:                      BGP_TYPE_OPEN,
		Version:                  BGP_VERSION,
		MyAS:                     []byte{0x00, 0x01},
		HoldTime:                 []byte{0x00, 0xb4},             // 180
		Identifier:               []byte{0xac, 0x11, 0x00, 0x04}, // 172.17.0.4
		OptionalParametersLength: 0x00,
	}
	b.Length = []byte{0x00, 0x1d} // 29. すべてのフィールドの長さを足した数
	return b
}

func (b *BGP) Bytes() []byte {
	buf := &bytes.Buffer{}
	buf.Write(b.Marker)
	buf.Write(b.Length)
	buf.WriteByte(b.Typ)
	buf.WriteByte(b.Version)
	buf.Write(b.MyAS)
	buf.Write(b.HoldTime)
	buf.Write(b.Identifier)
	buf.WriteByte(b.OptionalParametersLength)
	return buf.Bytes()
}
