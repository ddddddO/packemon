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
func StrIPToBytes(s string) ([]byte, error) {
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

// TODO: rename or refactor
func StrHexToBytes(s string) ([]byte, error) {
	n, err := strconv.ParseUint(s, 0, 48)
	if err != nil {
		return nil, err
	}

	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, n)
	return buf[2:], nil
}

// TODO: rename or refactor
func StrHexToBytes2(s string) ([]byte, error) {
	n, err := strconv.ParseUint(s, 0, 16)
	if err != nil {
		return nil, err
	}

	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, uint16(n))
	return buf, nil
}

// TODO: rename or refactor
func StrHexToBytes3(s string) (byte, error) {
	n, err := strconv.ParseUint(s, 0, 8)
	if err != nil {
		return 0, err
	}

	return uint8(n), nil
}

func StrIntToUint16(s string) (uint16, error) {
	n, err := strconv.ParseUint(s, 0, 16)
	if err != nil {
		return 0, err
	}
	return uint16(n), nil
}

// copy of https://github.com/sat0ken/go-curo/blob/main/utils.go#L18
func calculateChecksum(packet []byte) []byte {
	// まず16ビット毎に足す
	sum := sumByteArr(packet)
	// あふれた桁を足す
	sum = (sum & 0xffff) + sum>>16
	// 論理否定を取った値をbyteにして返す
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, uint16(sum^0xffff))
	return b
}

func sumByteArr(packet []byte) (sum uint) {
	for i := range packet {

		// ここ足した. icmpのreply返ってきてるし大丈夫そう
		if (i == len(packet)-2) && (len(packet)%2 != 0) {
			sum += uint(packet[i])
			break
		}

		if i%2 == 0 {
			sum += uint(binary.BigEndian.Uint16(packet[i:]))
		}
	}
	return sum
}
