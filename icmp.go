package packemon

import (
	"bytes"
	"encoding/binary"
	"time"
)

// https://www.infraexpert.com/study/tcpip4.html
// https://inc0x0.com/icmp-ip-packets-ping-manually-create-and-send-icmp-ip-packets/
type ICMP struct {
	Typ        uint8
	Code       uint8
	Checksum   uint16
	Identifier uint16
	Sequence   uint16
	Data       []byte
}

const (
	ICMP_TYPE_REQUEST = 0x08
)

// icmp request
func NewICMP() *ICMP {
	icmp := &ICMP{
		Typ:        ICMP_TYPE_REQUEST,
		Code:       0,
		Identifier: 0x34a1,
		Sequence:   0x0001,
	}

	// pingのecho requestのpacketを観察すると以下で良さそう
	timestamp := func() []byte {
		now := time.Now().Unix()
		b := make([]byte, 4)
		binary.LittleEndian.PutUint32(b, uint32(now))
		return binary.LittleEndian.AppendUint32(b, 0x00000000)
	}()

	icmp.Data = timestamp

	icmp.Checksum = func() uint16 {
		b := make([]byte, 2)
		binary.LittleEndian.PutUint16(b, icmp.CalculateChecksum())
		return binary.BigEndian.Uint16(b)
	}()

	return icmp
}

// copy from https://cs.opensource.google/go/x/net/+/master:icmp/message.go
func (i *ICMP) CalculateChecksum() uint16 {
	b := i.Bytes()
	csumcv := len(b) - 1 // checksum coverage
	s := uint32(0)
	for i := 0; i < csumcv; i += 2 {
		s += uint32(b[i+1])<<8 | uint32(b[i])
	}
	if csumcv&1 == 0 {
		s += uint32(b[csumcv])
	}
	s = s>>16 + s&0xffff
	s = s + s>>16
	return ^uint16(s)
}

func (i *ICMP) Bytes() []byte {
	buf := &bytes.Buffer{}
	buf.WriteByte(i.Typ)
	buf.WriteByte(i.Code)
	WriteUint16(buf, i.Checksum)
	WriteUint16(buf, i.Identifier)
	WriteUint16(buf, i.Sequence)
	buf.Write(i.Data)
	return buf.Bytes()
}
