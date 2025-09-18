package packemon

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
)

type UDP struct {
	SrcPort  uint16
	DstPort  uint16
	Length   uint16
	Checksum uint16 // TODO: 後で計算用メソッドを。そもそも他のヘッダのchecksumと同じ計算っぽいから、独立させるかも
	Data     []byte
}

func ParsedUDP(payload []byte) *UDP {
	return &UDP{
		SrcPort:  binary.BigEndian.Uint16(payload[0:2]),
		DstPort:  binary.BigEndian.Uint16(payload[2:4]),
		Length:   binary.BigEndian.Uint16(payload[4:6]),
		Checksum: binary.BigEndian.Uint16(payload[6:8]),
		Data:     payload[8:],
	}
}

func (u *UDP) Len() {
	length := 0
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, u.SrcPort)
	length += len(b)

	b = make([]byte, 2)
	binary.BigEndian.PutUint16(b, u.DstPort)
	length += len(b)

	b = make([]byte, 2)
	binary.BigEndian.PutUint16(b, u.Length)
	length += len(b)

	b = make([]byte, 2)
	binary.BigEndian.PutUint16(b, u.Checksum)
	length += len(b)

	length += len(u.Data)
	u.Length = uint16(length)
}

func (u *UDP) CalculateChecksum(ipv4 *IPv4) {
	pseudoHeaderIPv4 := func() []byte {
		buf := &bytes.Buffer{}
		binary.Write(buf, binary.BigEndian, ipv4.SrcAddr)
		binary.Write(buf, binary.BigEndian, ipv4.DstAddr)
		buf.WriteByte(0x00)
		buf.WriteByte(ipv4.Protocol)
		u.Len()
		WriteUint16(buf, u.Length)
		return buf.Bytes()
	}

	forUDPChecksum := &bytes.Buffer{}
	forUDPChecksum.Write(pseudoHeaderIPv4())
	forUDPChecksum.Write(u.Bytes())
	if len(u.Data)%2 != 0 {
		forUDPChecksum.WriteByte(0x00)
	}

	data := forUDPChecksum.Bytes()
	u.Checksum = binary.BigEndian.Uint16(calculateChecksum(data))
}

// IPv6 ではチェックサムがないため、上のレイヤでチェックサムが必要なため
func (u *UDP) CalculateChecksumForIPv6(ipv6 *IPv6) {
	pseudoHeader := ipv6.PseudoHeader(uint32(u.Length))
	forUDPChecksum := &bytes.Buffer{}
	forUDPChecksum.Write(pseudoHeader)
	forUDPChecksum.Write(u.Bytes())
	if len(u.Data)%2 != 0 {
		forUDPChecksum.WriteByte(0x00)
	}

	data := forUDPChecksum.Bytes()
	u.Checksum = binary.BigEndian.Uint16(calculateChecksum(data))
}

func (u *UDP) Bytes() []byte {
	buf := &bytes.Buffer{}
	WriteUint16(buf, u.SrcPort)
	WriteUint16(buf, u.DstPort)
	WriteUint16(buf, u.Length)
	WriteUint16(buf, u.Checksum)
	buf.Write(u.Data)
	return buf.Bytes()
}

func createUDPAddr(ipBytes []byte, port uint16) (*net.UDPAddr, error) {
	if len(ipBytes) != net.IPv4len && len(ipBytes) != net.IPv6len {
		return nil, fmt.Errorf("invalid IP addr length: %d bytes", len(ipBytes))
	}

	return &net.UDPAddr{
		IP:   net.IP(ipBytes),
		Port: int(port),
	}, nil
}
