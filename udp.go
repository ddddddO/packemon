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
	writeUint16(buf, u.SrcPort)
	writeUint16(buf, u.DstPort)
	writeUint16(buf, u.Length)
	writeUint16(buf, u.Checksum)
	buf.Write(u.Data)
	return buf.Bytes()
}
