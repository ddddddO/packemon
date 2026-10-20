package packemon

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestCalculateChecksum(t *testing.T) {
	tests := []struct {
		name   string
		packet []byte
		want   uint16
	}{
		{
			// ref: https://en.wikipedia.org/wiki/Internet_checksum
			name:   "ipv4 header",
			packet: []byte{0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7},
			want:   0xb861,
		},
		{
			// 1回目の桁あふれの加算で、再度桁あふれする
			name:   "carry twice",
			packet: []byte{0xff, 0xff, 0xff, 0xff, 0x00, 0x01},
			want:   0xfffe,
		},
		{
			name:   "odd length",
			packet: []byte{0x12, 0x34, 0x56, 0x78, 0x9a},
			want:   0xfd52,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := binary.BigEndian.Uint16(calculateChecksum(tt.packet))
			if got != tt.want {
				t.Fatalf("calculateChecksum() = 0x%04x, want 0x%04x", got, tt.want)
			}
		})
	}
}

func TestIPv4_fragmentOffset(t *testing.T) {
	ipv4 := NewIPv4(IPv4_PROTO_UDP, 0xc0a80001, 0xc0a80002)
	ipv4.Flags = 0x20 // More Fragments
	ipv4.FragmentOffset = 185
	ipv4.CalculateChecksum()

	b := ipv4.Bytes()
	if !bytes.Equal(b[6:8], []byte{0x20, 0xb9}) {
		t.Fatalf("flags and fragment offset = %x, want 20b9", b[6:8])
	}
	if b[8] != ipv4.Ttl {
		t.Fatalf("ttl = 0x%02x, want 0x%02x", b[8], ipv4.Ttl)
	}
	// ヘッダチェックサム込みで計算し直すと0になること
	if got := binary.BigEndian.Uint16(calculateChecksum(b[:20])); got != 0 {
		t.Fatalf("invalid header checksum: 0x%04x", ipv4.HeaderChecksum)
	}

	parsed := ParsedIPv4(b)
	if parsed.Flags != 0x20 || parsed.FragmentOffset != 185 {
		t.Fatalf("parsed flags = 0x%02x, fragment offset = %d", parsed.Flags, parsed.FragmentOffset)
	}
}
