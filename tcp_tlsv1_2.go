package packemon

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"net"
	"time"
)

const IP_PAYLOAD_MAX_LENGTH = 1500 - 14 // =1486byte(IPヘッダ含む。14byteはEthernetヘッダ分)

/*
- 任意のsrcIPを指定できるけど、NICに紐づいたIPでないとエラーになるよう
- 指定できるのが以下でそれ以外はダメ
  - IPv4: Source IP Addr, Destination IP Addr
  - TCP: Source Port, Destination Port
  - Application Protocol
*/
func establishTCPTLSv1_2AndSendPayload(ctx context.Context, fIpv4 *IPv4, fTcp *TCP, upperLayerData []byte) error {
	network := "tcp"

	localIPBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(localIPBytes, fIpv4.SrcAddr)
	localTCPAddr, err := createTCPAddr(localIPBytes, fTcp.SrcPort)
	if err != nil {
		return err
	}

	remoteIPBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(remoteIPBytes, fIpv4.DstAddr)
	remoteTCPAddr, err := createTCPAddr(remoteIPBytes, fTcp.DstPort)
	if err != nil {
		return err
	}

	tcpConn, err := net.DialTCP(network, localTCPAddr, remoteTCPAddr)
	if err != nil {
		return err
	}
	defer tcpConn.Close()

	// TODO: 他で設定してたタイムアウト値外だしして使うように
	if err := tcpConn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}

	tlsCfg := &tls.Config{
		InsecureSkipVerify: true,
		// ServerName: ,
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS12,
	}
	tlsConn := tls.Client(tcpConn, tlsCfg)
	defer tlsConn.Close()

	if _, err := tlsConn.Write(upperLayerData); err != nil {
		return err
	}

	return nil
}

/*
- 任意のsrcIPを指定できるけど、NICに紐づいたIPでないとエラーになるよう
- 指定できるのが以下でそれ以外はダメ
  - IPv6: Source IP Addr, Destination IP Addr
  - TCP: Source Port, Destination Port
  - Application Protocol
*/
func establishTCPTLSv1_2AndSendPayloadForIPv6(ctx context.Context, fIpv6 *IPv6, fTcp *TCP, upperLayerData []byte) error {
	network := "tcp"

	localTCPAddr, err := createTCPAddr(fIpv6.SrcAddr, fTcp.SrcPort)
	if err != nil {
		return err
	}

	remoteTCPAddr, err := createTCPAddr(fIpv6.DstAddr, fTcp.DstPort)
	if err != nil {
		return err
	}

	tcpConn, err := net.DialTCP(network, localTCPAddr, remoteTCPAddr)
	if err != nil {
		return err
	}
	defer tcpConn.Close()

	// TODO: 他で設定してたタイムアウト値外だしして使うように
	if err := tcpConn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}

	tlsCfg := &tls.Config{
		InsecureSkipVerify: true,
		// ServerName: ,
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS12,
	}
	tlsConn := tls.Client(tcpConn, tlsCfg)
	defer tlsConn.Close()

	if _, err := tlsConn.Write(upperLayerData); err != nil {
		return err
	}

	return nil
}

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
