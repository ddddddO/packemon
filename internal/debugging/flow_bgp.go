package debugging

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"time"

	p "github.com/ddddddO/packemon"
	"golang.org/x/sys/unix"
)

const BGP_PORT = 0x00b3 // 179

func (dnw *debugNetworkInterface) FlowBGP() error {
	var srcPort uint16 = 0x2797 // TODO: 毎回変えること
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

	prevSentBGPOpen := false
	prevPassiveKeepalive := false

	var tmpSeqForKeepalive uint32
	var tmpAckForKeepalive uint32

	triggerBGPNotification := 3 // 一旦 keepalive を3回受信後にこちらから Notification 投げる
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
						prevSentBGPOpen = true
						continue
					}

					if tcp.Flags == p.TCP_FLAGS_ACK {
						log.Println("passive TCP_FLAGS_ACK")
						continue
					}

					if tcp.Flags == p.TCP_FLAGS_PSH_ACK {
						log.Println("passive TCP_FLAGS_PSH_ACK")

						// ここで対向から BGP の OPEN / KEEPALIVE / UPDATE / NOTIFICATION が取れる
						if IsBGPOpen(tcp.Data) {
							fmt.Println("Open")
							bgpopen := ParsedBGPOpen(tcp.Data)
							fmt.Printf("%x\n", bgpopen.Typ)

							// Ack
							tcp := p.NewTCPAckForPassiveData(srcPort, dstPort, tcp.Sequence, tcp.Acknowledgment, 102 /* TODO: ほんとは、bgpopen.Length を int にしたものを */)
							ipv4 := p.NewIPv4(p.IPv4_PROTO_TCP, srcIPAddr, dstIPAddr)
							tcp.CalculateChecksum(ipv4)
							ipv4.Data = tcp.Bytes()
							ipv4.CalculateTotalLength()
							ipv4.CalculateChecksum()
							ethernetFrame := p.NewEthernetFrame(dstMACAddr, srcMACAddr, p.ETHER_TYPE_IPv4, ipv4.Bytes())
							if err := dnw.Send(ethernetFrame); err != nil {
								return err
							}

							tmpSeqForKeepalive = tcp.Sequence
							tmpAckForKeepalive = tcp.Acknowledgment

							continue
						}

						if IsBGPKeepalive(tcp.Data) {
							fmt.Println("Keepalive")

							triggerBGPNotification--
							prevPassiveKeepalive = true

							// Ack
							tcp := p.NewTCPAckForPassiveData(srcPort, dstPort, tcp.Sequence, tcp.Acknowledgment, 19 /* TODO: ほんとは、.Length を int にしたものを */)
							ipv4 := p.NewIPv4(p.IPv4_PROTO_TCP, srcIPAddr, dstIPAddr)
							tcp.CalculateChecksum(ipv4)
							ipv4.Data = tcp.Bytes()
							ipv4.CalculateTotalLength()
							ipv4.CalculateChecksum()
							ethernetFrame := p.NewEthernetFrame(dstMACAddr, srcMACAddr, p.ETHER_TYPE_IPv4, ipv4.Bytes())
							if err := dnw.Send(ethernetFrame); err != nil {
								return err
							}

							if triggerBGPNotification == 0 {
								fmt.Println("Sent BGP Notification")
								if err := dnw.BGPNotification(srcPort, dstPort, srcIPAddr, dstIPAddr, dstMACAddr, tcp.Sequence, tcp.Acknowledgment); err != nil {
									return err
								}
								continue
							}

							if prevSentBGPOpen {
								// ここで、Keepalive 送るみたい。キャプチャ見ると
								// TODO: ここで送った後は、ticker か何か使って一定周期で keepalive 送るようにする?現状、対向の keepalive 受信後にこちらも送信としてる
								if err := dnw.BGPKeepalive(srcPort, dstPort, srcIPAddr, dstIPAddr, dstMACAddr, tmpSeqForKeepalive, tmpAckForKeepalive); err != nil {
									return err
								}
								prevSentBGPOpen = false
								fmt.Println("Sent BGP Keepalive")

								if prevPassiveKeepalive {
								BREAK:
									// 送った keepalive の ack を受信する
									for {
										fmt.Println("Waiting passive Ack of keepalive...")

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
													if tcp.Flags == p.TCP_FLAGS_ACK {
														time.Sleep(1000 * time.Millisecond)
														if err := dnw.BGPUpdate(srcPort, dstPort, srcIPAddr, dstIPAddr, dstMACAddr, tcp.Acknowledgment, tcp.Sequence); err != nil {
															fmt.Fprintln(os.Stderr, err)
														}
														fmt.Println("Sent BGP Update")
														prevPassiveKeepalive = false

														break BREAK
													}
												}
											}
										}
									}
								}
							} else {
								if err := dnw.BGPKeepalive(srcPort, dstPort, srcIPAddr, dstIPAddr, dstMACAddr, tcp.Sequence, tcp.Acknowledgment); err != nil {
									return err
								}
								fmt.Println("Sent BGP Keepalive")
							}
						}

						if IsBGPUpdate(tcp.Data) {
							fmt.Println("Update")

							// Ack
							tcp := p.NewTCPAckForPassiveData(srcPort, dstPort, tcp.Sequence, tcp.Acknowledgment, 23 /* TODO: ほんとは、.Length を int にしたものを */)
							ipv4 := p.NewIPv4(p.IPv4_PROTO_TCP, srcIPAddr, dstIPAddr)
							tcp.CalculateChecksum(ipv4)
							ipv4.Data = tcp.Bytes()
							ipv4.CalculateTotalLength()
							ipv4.CalculateChecksum()
							ethernetFrame := p.NewEthernetFrame(dstMACAddr, srcMACAddr, p.ETHER_TYPE_IPv4, ipv4.Bytes())
							if err := dnw.Send(ethernetFrame); err != nil {
								return err
							}
							continue
						}

						if IsBGPNotification(tcp.Data) {
							fmt.Println("Notification")
							continue
						}

						continue
					}

					if tcp.Flags == p.TCP_FLAGS_FIN_ACK {
						log.Println("passive TCP_FLAGS_FIN_ACK")

						// Ack
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
						return nil
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

func (dnw *debugNetworkInterface) BGPKeepalive(srcPort, dstPort uint16, srcIPAddr uint32, dstIPAddr uint32, firsthopMACAddr [6]byte, prevSequence uint32, prevAcknowledgment uint32) error {
	bgpkeepalive := NewBGPKeepalive()
	tcp := p.NewTCPWithData(srcPort, dstPort, bgpkeepalive.Bytes(), prevSequence, prevAcknowledgment)
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

func (dnw *debugNetworkInterface) BGPUpdate(srcPort, dstPort uint16, srcIPAddr uint32, dstIPAddr uint32, firsthopMACAddr [6]byte, prevSequence uint32, prevAcknowledgment uint32) error {
	bgpupdate := NewBGPUpdate()
	tcp := p.NewTCPWithData(srcPort, dstPort, bgpupdate.Bytes(), prevSequence, prevAcknowledgment)
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

func (dnw *debugNetworkInterface) BGPNotification(srcPort, dstPort uint16, srcIPAddr uint32, dstIPAddr uint32, firsthopMACAddr [6]byte, prevSequence uint32, prevAcknowledgment uint32) error {
	bgpnotification := NewBGPNotification()
	tcp := p.NewTCPWithData(srcPort, dstPort, bgpnotification.Bytes(), prevSequence, prevAcknowledgment)
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

const (
	BGP_TYPE_OPEN          = 0x01
	BGP_TYPE_UPDATE        = 0x02
	BGP_TYPE_NOTIFICATION  = 0x03
	BGP_TYPE_KEEPALIVE     = 0x04
	BGP_TYPE_ROUTERREFRESH = 0x05
)

const BGP_VERSION = 0x04

// すべて1の場合は認証なし. TODO: 認証ある場合
var BGP_MARKER = []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

// https://support.hpe.com/techhub/eginfolib/networking/docs/switches/3600v2/5998-7619r_l3-ip-rtng_cg/content/442284290.htm
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

// 上の BGP strucct とフィールドが微妙に異なる
type BGPUpdateStruct struct {
	Marker                   []byte // 16byte
	Length                   []byte // 2byte
	Typ                      byte   // 1byte
	WithdrawnRoutesLength    []byte // 2byte
	TotalPathAttributeLength []byte // 2byte
}

// 上の BGP strucct とフィールドが微妙に異なる
type BGPNotificationStruct struct {
	Marker         []byte // 16byte
	Length         []byte // 2byte
	Typ            byte   // 1byte
	MajorErrorCode byte   // 1byte
	MinorErrorCode byte   // 1byte
}

func IsBGPOpen(payload []byte) bool {
	if !IsBGP(payload) {
		return false
	}

	typ := payload[18]
	return bytes.Equal([]byte{typ}, []byte{BGP_TYPE_OPEN})
}

func IsBGPUpdate(payload []byte) bool {
	if !IsBGP(payload) {
		return false
	}

	typ := payload[18]
	return bytes.Equal([]byte{typ}, []byte{BGP_TYPE_UPDATE})
}

func IsBGPKeepalive(payload []byte) bool {
	if !IsBGP(payload) {
		return false
	}

	typ := payload[18]
	return bytes.Equal([]byte{typ}, []byte{BGP_TYPE_KEEPALIVE})
}

func IsBGPNotification(payload []byte) bool {
	if !IsBGP(payload) {
		return false
	}

	typ := payload[18]
	return bytes.Equal([]byte{typ}, []byte{BGP_TYPE_NOTIFICATION})
}

func IsBGP(payload []byte) bool {
	if len(payload) < 19 {
		return false
	}

	marker := payload[0:16]
	return bytes.Equal(marker, BGP_MARKER)
}

func ParsedBGPOpen(payload []byte) *BGP {
	marker := payload[0:16]
	length := payload[16:18]
	typ := payload[18]
	version := payload[19]
	myas := payload[20:22]
	holdtime := payload[22:24]
	identifier := payload[24:30]
	optonalParametersLen := payload[30] // byte -> int 変換する

	return &BGP{
		Marker:                   marker,
		Length:                   length,
		Typ:                      typ,
		Version:                  version,
		MyAS:                     myas,
		HoldTime:                 holdtime,
		Identifier:               identifier,
		OptionalParametersLength: optonalParametersLen,
		// OptionalParameters: , // TODO:
	}
}

func ParsedBGPUpdate(payload []byte) *BGPUpdateStruct {
	marker := payload[0:16]
	length := payload[16:18]
	typ := payload[18]
	withdrawnRoutesLength := payload[19:21]
	totalPathAttributeLength := payload[21:23]

	return &BGPUpdateStruct{
		Marker:                   marker,
		Length:                   length,
		Typ:                      typ,
		WithdrawnRoutesLength:    withdrawnRoutesLength,
		TotalPathAttributeLength: totalPathAttributeLength,
	}
}

func NewBGPOpen() *BGP {
	b := &BGP{
		Marker:                   BGP_MARKER,
		Typ:                      BGP_TYPE_OPEN,
		Version:                  BGP_VERSION,
		MyAS:                     []byte{0x00, 0x01},
		HoldTime:                 []byte{0x00, 0xb4},             // 180
		Identifier:               []byte{0xac, 0x11, 0x00, 0x04}, // 172.17.0.4
		OptionalParametersLength: 0x49,                           // 73
		OptionalParameters:       tmpOptionalParameters(),
	}
	b.Length = []byte{0x00, 0x66} // 102. すべてのフィールドの長さを足した数
	return b
}

// TODO: ちゃんと...
// また、これは frr の BGP Open をパケットキャプチャしてその値をべた書きしたもの
func tmpOptionalParameters() []byte {
	return []byte{
		0x02, 0x06, 0x01, 0x04, 0x00, 0x01, 0x00, 0x01, 0x02, 0x02, 0x80, 0x00, 0x02, 0x02, 0x02, 0x00,
		0x02, 0x02, 0x46, 0x00, 0x02, 0x06, 0x41, 0x04, 0x00, 0x00, 0x00, 0x01, 0x02, 0x02, 0x06, 0x00,
		0x02, 0x06, 0x45, 0x04, 0x00, 0x01, 0x01, 0x01, 0x02, 0x0e, 0x49, 0x0c, 0x0a, 0x42, 0x47, 0x50,
		0x52, 0x6f, 0x75, 0x74, 0x65, 0x72, 0x31, 0x00, 0x02, 0x04, 0x40, 0x02, 0xc0, 0x78, 0x02, 0x09,
		0x47, 0x07, 0x00, 0x01, 0x01, 0x80, 0x00, 0x00, 0x00,
	}
}

func NewBGPKeepalive() *BGP {
	b := &BGP{
		Marker: BGP_MARKER,
		Length: []byte{0x00, 0x13}, // 19
		Typ:    BGP_TYPE_KEEPALIVE,
	}
	return b
}

func NewBGPUpdate() *BGPUpdateStruct {
	bu := &BGPUpdateStruct{
		Marker:                   BGP_MARKER,
		Length:                   []byte{0x00, 0x17}, // 23
		Typ:                      BGP_TYPE_UPDATE,
		WithdrawnRoutesLength:    []byte{0x00, 0x00},
		TotalPathAttributeLength: []byte{0x00, 0x00},
	}
	return bu
}

// https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml#bgp-parameters-3
const BGP_MAJOR_ERROR_MESSAGE_HEADER_ERROR = 0x01

const BGP_MINOR_ERROR_CONNECTION_NOT_SYNCHRONIZED = 0x01

func NewBGPNotification() *BGPNotificationStruct {
	bn := &BGPNotificationStruct{
		Marker:         BGP_MARKER,
		Length:         []byte{0x00, 0x15}, // 21
		Typ:            BGP_TYPE_NOTIFICATION,
		MajorErrorCode: BGP_MAJOR_ERROR_MESSAGE_HEADER_ERROR,
		MinorErrorCode: BGP_MINOR_ERROR_CONNECTION_NOT_SYNCHRONIZED,
	}
	return bn
}

func (b *BGP) Bytes() []byte {
	buf := &bytes.Buffer{}
	buf.Write(b.Marker)
	buf.Write(b.Length)
	buf.WriteByte(b.Typ)
	if b.Typ == BGP_TYPE_KEEPALIVE {
		return buf.Bytes()
	}

	buf.WriteByte(b.Version)
	buf.Write(b.MyAS)
	buf.Write(b.HoldTime)
	buf.Write(b.Identifier)
	buf.WriteByte(b.OptionalParametersLength)
	buf.Write(b.OptionalParameters)
	return buf.Bytes()
}

func (bu *BGPUpdateStruct) Bytes() []byte {
	buf := &bytes.Buffer{}
	buf.Write(bu.Marker)
	buf.Write(bu.Length)
	buf.WriteByte(bu.Typ)
	buf.Write(bu.WithdrawnRoutesLength)
	buf.Write(bu.TotalPathAttributeLength)
	return buf.Bytes()
}

func (bn *BGPNotificationStruct) Bytes() []byte {
	buf := &bytes.Buffer{}
	buf.Write(bn.Marker)
	buf.Write(bn.Length)
	buf.WriteByte(bn.Typ)
	buf.WriteByte(bn.MajorErrorCode)
	buf.WriteByte(bn.MinorErrorCode)
	return buf.Bytes()
}
