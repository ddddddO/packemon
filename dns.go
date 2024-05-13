package packemon

import (
	"bytes"
	"strings"
)

const PORT_DNS = 0x0035 // 53

// TODO: 雑にFlagsを定義しちゃってる。ほんとはビット単位
const (
	DNS_REQUEST  = 0x0100
	DNS_RESPONSE = 0x8180
)

const (
	DNS_QUERY_TYPE_A    = 0x0001
	DNS_QUERY_TYPE_AAAA = 0x001c
)

const (
	DNS_QUERY_CLASS_IN = 0x0001
)

// https://atmarkit.itmedia.co.jp/ait/articles/1601/29/news014.html
// 上記とパケットキャプチャ見てイメージがつく、domain
type DNS struct {
	TransactionID uint16
	Flags         uint16 // TODO: ここにビット単位で意味があるから、structにして管理したい
	Questions     uint16
	AnswerRRs     uint16
	AuthorityRRs  uint16
	AdditionalRRs uint16
	Queries       *Queries
	Answers       []*Answer
}

// TODO: 個別にQueryで定義してスライスで持つようにする
type Queries struct {
	Domain     []uint8
	Typ        uint16
	Class      uint16
	Ttl        uint32
	DataLength uint16
}

type Answer struct {
	Name       uint16
	Typ        uint16
	Class      uint16
	Ttl        uint32
	DataLength uint16
	Address    uint32
}

func (d *DNS) Domain(domain string) {
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
	d.Queries.Domain = buf
}

func (d *DNS) Bytes() []byte {
	buf := &bytes.Buffer{}
	WriteUint16(buf, d.TransactionID)
	WriteUint16(buf, d.Flags)
	WriteUint16(buf, d.Questions)
	WriteUint16(buf, d.AnswerRRs)
	WriteUint16(buf, d.AuthorityRRs)
	WriteUint16(buf, d.AdditionalRRs)
	buf.Write(d.Queries.Domain)
	WriteUint16(buf, d.Queries.Typ)
	WriteUint16(buf, d.Queries.Class)
	return buf.Bytes()
}
