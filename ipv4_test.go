package packemon_test

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

func Test_sandbox(t *testing.T) {
	p0 := []byte{0x08, 0x06}
	var p1, p2 uint16
	if err := binary.Read(bytes.NewReader(p0), binary.BigEndian, &p1); err != nil {
		t.Fatal(err)
	}
	p2 = binary.BigEndian.Uint16(p0)
	if p1 != p2 {
		t.Errorf("p1とp2一致しませんでした. p1: %x, p2: %x", p1, p2)
	}

	// ビット操作
	// ref: https://www.flyenginer.com/low/go/go%E3%81%AE%E3%83%93%E3%83%83%E3%83%88%E6%BC%94%E7%AE%97%E3%81%AB%E3%81%A4%E3%81%84%E3%81%A6.html
	var p3 uint8 = 0x01
	var p4 uint8 = 0x10
	t.Logf("want: %x,  got: %x", 0x01, (p3 | p3))
	t.Logf("want: %x,  got: %x", 0x11, (p3 | p4))
	t.Logf("want: %x,  got: %x", 0x01, (p3 & p3))
	t.Logf("want: %x,  got: %x", 0x00, (p3 & p4))
	t.Logf("want: %x,  got: %x", 0x00, (p3 ^ p3))
	t.Logf("want: %x,  got: %x", 0x11, (p3 ^ p4))

	var p5 uint8 = 0x0b // 11. bitで表すと, 00001011
	// 2bit左シフト. 0x2c = 44 = 00101100
	t.Logf("want: %x, got: %x", 0x2c, (p5 << 2))
	// 3bit右シフト. 0x01 = 1 = 00000001
	t.Logf("want: %x, got: %x", 0x01, (p5 >> 3))
	// 4bit左シフトして2bit右シフト. 00101100
	t.Logf("want: %x, got: %x", 0x2c, (p5 << 4 >> 2))

	var buf1, buf2 bytes.Buffer
	var p6 uint8 = 0x0f // 00001111
	buf1.WriteByte(p6)
	buf2.WriteByte(p6 << 2) // 00111100
	t.Logf("buf1 bytes(want: 0f): %x", buf1.Bytes())
	t.Logf("buf2 bytes(want: 3c): %x", buf2.Bytes())
	buf1.WriteByte(0x0e)
	t.Logf("buf1 bytes(want: 0f0e): %x = %b", buf1.Bytes(), buf1.Bytes())
	buf1.WriteByte(0x07)
	t.Logf("buf1 bytes(want: 0f0e07): %x = %b(= [1111 1110 111])", buf1.Bytes(), buf1.Bytes())

	now := time.Now().Unix()
	t.Logf("unixtime: %d\n", now)
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, uint32(now))
	t.Logf("unixtime bytes: %x\n", b) // リトルエンディアンでicmpのtimestampに詰めればよさそう
	b = make([]byte, 4)
	binary.LittleEndian.PutUint32(b, uint32(now))
	t.Logf("unixtime bytes(lit): %x\n", b) // これで良さそうtimestampは
	b = binary.LittleEndian.AppendUint32(b, 0x00000000)
	t.Logf("icmp timestamp: %x\n", b)

	var buf3, buf4 bytes.Buffer
	var p7 uint16 = 0x00a0
	var p8 uint16 = 0x002
	t.Logf("p7: %b", p7)
	t.Logf("p8: %b", p8)
	t.Logf("p7   : %b", p7)
	t.Logf("p7'  : %b", p7<<2)
	t.Logf("p7'' : %b", p7<<3)
	t.Logf("p7''': %b", p7<<8)
	b = make([]byte, 2)
	binary.BigEndian.PutUint16(b, p7)
	buf3.Write(b)
	t.Logf("buf3 bytes(want: xx): %x", buf3.Bytes())

	t.Logf("p7 p8: %x", p7<<8|p8)
	b = make([]byte, 2)
	binary.BigEndian.PutUint16(b, p7<<8|p8)
	buf4.Write(b)
	t.Logf("buf4 bytes(want: xx): %x", buf4.Bytes())
}
