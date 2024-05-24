package packemon

import (
	"bytes"
	"encoding/binary"
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

func ParsedDNSRequest(payload []byte) *DNS {
	flags := binary.BigEndian.Uint16(payload[2:4])
	qCnt := binary.BigEndian.Uint16(payload[4:6])
	anCnt := binary.BigEndian.Uint16(payload[6:8])
	auCnt := binary.BigEndian.Uint16(payload[8:10])
	adCnt := binary.BigEndian.Uint16(payload[10:12])
	// 一旦Questionsは1固定で進める
	// また、domainは、0x00 までとなる。そういう判定処理
	offset := bytes.IndexByte(payload[12:], 0x00) + 12 + 1
	q := &Queries{
		Domain: payload[12:offset],
		Typ:    binary.BigEndian.Uint16(payload[offset : offset+2]),
		Class:  binary.BigEndian.Uint16(payload[offset+2 : offset+4]),
	}

	return &DNS{
		TransactionID: binary.BigEndian.Uint16(payload[0:2]),
		Flags:         flags,
		Questions:     qCnt,
		AnswerRRs:     anCnt,
		AuthorityRRs:  auCnt,
		AdditionalRRs: adCnt,
		Queries:       q,
	}
}

func ParsedDNSResponse(payload []byte) *DNS {
	flags := binary.BigEndian.Uint16(payload[2:4])
	qCnt := binary.BigEndian.Uint16(payload[4:6])
	anCnt := binary.BigEndian.Uint16(payload[6:8])
	auCnt := binary.BigEndian.Uint16(payload[8:10])
	adCnt := binary.BigEndian.Uint16(payload[10:12])

	// 一旦Questionsは1固定として進める
	// また、domainは、0x00 までとなる。そういう判定処理
	offset := bytes.IndexByte(payload[12:], 0x00) + 12 + 1
	q := &Queries{
		Domain: payload[12:offset],
		Typ:    binary.BigEndian.Uint16(payload[offset : offset+2]),
		Class:  binary.BigEndian.Uint16(payload[offset+2 : offset+4]),
	}
	// 一旦Answersは1固定として進める
	offsetOfAns := offset + 4
	a := &Answer{
		Name:       binary.BigEndian.Uint16(payload[offsetOfAns : offsetOfAns+2]),
		Typ:        binary.BigEndian.Uint16(payload[offsetOfAns+2 : offsetOfAns+4]),
		Class:      binary.BigEndian.Uint16(payload[offsetOfAns+4 : offsetOfAns+6]),
		Ttl:        binary.BigEndian.Uint32(payload[offsetOfAns+6 : offsetOfAns+10]),
		DataLength: binary.BigEndian.Uint16(payload[offsetOfAns+10 : offsetOfAns+12]),
		Address:    binary.BigEndian.Uint32(payload[offsetOfAns+12 : offsetOfAns+16]),
	}

	return &DNS{
		TransactionID: binary.BigEndian.Uint16(payload[0:2]),
		Flags:         flags,
		Questions:     qCnt,
		AnswerRRs:     anCnt,
		AuthorityRRs:  auCnt,
		AdditionalRRs: adCnt,
		Queries:       q,
		Answers:       []*Answer{a},
	}
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
