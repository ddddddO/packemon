package packemon

import (
	"bytes"
	"encoding/binary"
	"strconv"
	"strings"
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

// stringのIPv4アドレスをbytesに変換
func strIPToBytes(s string) ([]byte, error) {
	b := make([]byte, 4)
	src := strings.Split(s, ".")

	for i := range src {
		if len(src[i]) == 0 {
			continue
		}
		ip, err := strconv.ParseUint(src[i], 10, 8)
		if err != nil {
			return nil, err
		}
		b[i] = byte(ip)
	}
	return b, nil
}
