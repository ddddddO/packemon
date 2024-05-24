package packemon

import (
	"bytes"
	"encoding/binary"
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

func (u *UDP) Bytes() []byte {
	buf := &bytes.Buffer{}
	WriteUint16(buf, u.SrcPort)
	WriteUint16(buf, u.DstPort)
	WriteUint16(buf, u.Length)
	WriteUint16(buf, u.Checksum)
	buf.Write(u.Data)
	return buf.Bytes()
}
