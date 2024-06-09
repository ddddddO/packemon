package packemon

import "bytes"

type Mss struct {
	Kind   uint8
	Length uint8
	Value  uint16
}

type SackPermitted struct {
	Kind   uint8
	Length uint8
}

type Timestamps struct {
	Kind      uint8
	Length    uint8
	Value     uint32
	EchoReply uint32
}

type NoOperation struct {
	Kind uint8
}

type WindowScale struct {
	Kind       uint8
	Length     uint8
	ShiftCount uint8
}

// synパケットの中を覗いて下
func Options() []byte {
	buf := &bytes.Buffer{}

	m := &Mss{
		Kind:   0x02,
		Length: 0x04,
		Value:  0x05b4, // 1460
	}
	buf.WriteByte(m.Kind)
	buf.WriteByte(m.Length)
	WriteUint16(buf, m.Value)

	s := &SackPermitted{
		Kind:   0x04,
		Length: 0x02,
	}
	buf.WriteByte(s.Kind)
	buf.WriteByte(s.Length)

	t := &Timestamps{
		Kind:      0x08,
		Length:    0x0a,
		Value:     0xd4091f09,
		EchoReply: 0x00000000,
	}
	buf.WriteByte(t.Kind)
	buf.WriteByte(t.Length)
	WriteUint32(buf, t.Value)
	WriteUint32(buf, t.EchoReply)

	n := &NoOperation{
		Kind: 0x01,
	}
	buf.WriteByte(n.Kind)

	w := &WindowScale{
		Kind:       0x03,
		Length:     0x03,
		ShiftCount: 0x07,
	}
	buf.WriteByte(w.Kind)
	buf.WriteByte(w.Length)
	buf.WriteByte(w.ShiftCount)

	return buf.Bytes()
}

// synパケットの中を覗いて下
func OptionsOfAck() []byte {
	buf := &bytes.Buffer{}

	n := &NoOperation{
		Kind: 0x01,
	}
	buf.WriteByte(n.Kind)
	buf.WriteByte(n.Kind)

	t := &Timestamps{
		Kind:      0x08,
		Length:    0x0a,
		Value:     0xdbe1c2c4,
		EchoReply: 0x796a7651,
	}
	buf.WriteByte(t.Kind)
	buf.WriteByte(t.Length)
	WriteUint32(buf, t.Value)
	WriteUint32(buf, t.EchoReply)

	return buf.Bytes()
}

// http getリクエスト時のtcp optionを覗いて
// https://atmarkit.itmedia.co.jp/ait/articles/0401/29/news080_2.html
// 「オプション」フィールド：32bit単位で可変長
func OptionsOfhttp() []byte {
	buf := &bytes.Buffer{}

	n := &NoOperation{
		Kind: 0x01,
	}
	buf.WriteByte(n.Kind)
	buf.WriteByte(n.Kind)

	t := &Timestamps{
		Kind:      0x08,
		Length:    0x0a,
		Value:     0x5d1fbc0b,
		EchoReply: 0x7a7519d3,
	}
	buf.WriteByte(t.Kind)
	buf.WriteByte(t.Length)
	WriteUint32(buf, t.Value)
	WriteUint32(buf, t.EchoReply)
	// padding := []byte{0x00, 0x00, 0x00}
	// buf.Write(padding)

	return buf.Bytes()
}
