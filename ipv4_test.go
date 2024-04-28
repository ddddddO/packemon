package main

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func Test_sandbox(t *testing.T) {
	s := "hello"
	if s != "hello" {
		t.Errorf("ダメです: got: %s, want: %s", s, "kkk")
	}

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
	t.Logf("want: %x, got:%x", 0x2c, (p5 << 4 >> 2))
}
