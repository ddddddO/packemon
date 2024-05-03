package main

import (
	"bytes"
	"encoding/binary"
	"strings"
)

// https://atmarkit.itmedia.co.jp/ait/articles/1601/29/news014.html
// 上記とパケットキャプチャ見てイメージがつく、domain
type dns struct {
	transactionID uint16
	flags         uint16
	questions     uint16
	answerRRs     uint16
	authorityRRs  uint16
	additionalRRs uint16
	queries       *queries
}

type queries struct {
	domain []uint8
	typ    uint16
	class  uint16
}

func (d *dns) domain(domain string) {
	splited := strings.Split(domain, ".")
	buf := make([]uint8, len(domain)+2)

	cnt := 0
	for _, s := range splited {
		buf[cnt] = uint8(len(s))
		cnt++
		for _, c := range s {
			buf[cnt] = uint8(rune(c)) // ドメインに絵文字とか使えた気が。そうするとバグるはず
			cnt++
		}
	}

	buf[len(domain)+1] = 0x00
	d.queries.domain = buf
}

func (d *dns) toBytes() []byte {
	var buf bytes.Buffer
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, d.transactionID)
	buf.Write(b)

	b = make([]byte, 2)
	binary.BigEndian.PutUint16(b, d.flags)
	buf.Write(b)

	b = make([]byte, 2)
	binary.BigEndian.PutUint16(b, d.questions)
	buf.Write(b)

	b = make([]byte, 2)
	binary.BigEndian.PutUint16(b, d.answerRRs)
	buf.Write(b)

	b = make([]byte, 2)
	binary.BigEndian.PutUint16(b, d.authorityRRs)
	buf.Write(b)

	b = make([]byte, 2)
	binary.BigEndian.PutUint16(b, d.additionalRRs)
	buf.Write(b)

	buf.Write(d.queries.domain)

	b = make([]byte, 2)
	binary.BigEndian.PutUint16(b, d.queries.typ)
	buf.Write(b)

	b = make([]byte, 2)
	binary.BigEndian.PutUint16(b, d.queries.class)
	buf.Write(b)

	return buf.Bytes()
}
