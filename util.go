package packemon

import (
	"bytes"
	"encoding/binary"
)

func WriteUint16(buf *bytes.Buffer, target uint16) {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, target)
	buf.Write(b)
}

func WriteUint32(buf *bytes.Buffer, target uint32) {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, target)
	buf.Write(b)
}
