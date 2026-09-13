package packemon

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
)

const PORT_DNS = 0x0035 // 53

// https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1 の「QR」
// 関連: https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-5 の「Opcode」の逆引きは廃止（IQuery (Inverse Query, OBSOLETE)）
const (
	DNS_QR_REQUEST  = 0 << 15 // 0
	DNS_QR_RESPONSE = 1 << 15 // 1000 0000 0000 0000
)

func IsDNSRequest(flags uint16) bool {
	return !IsDNSResponse(flags)
}

func IsDNSResponse(flags uint16) bool {
	return flags&DNS_QR_RESPONSE == DNS_QR_RESPONSE
}

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

	answers := []*Answer{}
	for i := 0; i < int(anCnt); i++ {
		offsetOfAns := offset + 4 + (16 * i)
		a := &Answer{
			Name:       binary.BigEndian.Uint16(payload[offsetOfAns : offsetOfAns+2]),
			Typ:        binary.BigEndian.Uint16(payload[offsetOfAns+2 : offsetOfAns+4]),
			Class:      binary.BigEndian.Uint16(payload[offsetOfAns+4 : offsetOfAns+6]),
			Ttl:        binary.BigEndian.Uint32(payload[offsetOfAns+6 : offsetOfAns+10]),
			DataLength: binary.BigEndian.Uint16(payload[offsetOfAns+10 : offsetOfAns+12]),
			Address:    binary.BigEndian.Uint32(payload[offsetOfAns+12 : offsetOfAns+16]),
		}
		answers = append(answers, a)
	}

	return &DNS{
		TransactionID: binary.BigEndian.Uint16(payload[0:2]),
		Flags:         flags,
		Questions:     qCnt,
		AnswerRRs:     anCnt,
		AuthorityRRs:  auCnt,
		AdditionalRRs: adCnt,
		Queries:       q, // TODO: スライスで持つ
		Answers:       answers,
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

	buf[cnt] = 0x00
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
	for i := range d.Answers {
		WriteUint16(buf, d.Answers[i].Name)
		WriteUint16(buf, d.Answers[i].Typ)
		WriteUint16(buf, d.Answers[i].Class)
		WriteUint32(buf, d.Answers[i].Ttl)
		WriteUint16(buf, d.Answers[i].DataLength)
		WriteUint32(buf, d.Answers[i].Address)
	}
	return buf.Bytes()
}

// TCPでDNSクエリを投げるときは、DNSクエリ長を先頭につけるため
func (d *DNS) BytesForTCP() []byte {
	buf := make([]byte, 2)
	dnsQueryBytes := d.Bytes()
	length := len(dnsQueryBytes)
	binary.BigEndian.PutUint16(buf, uint16(length))
	return append(buf, dnsQueryBytes...)
}

// ScratchDNSAssembler は、スクラッチ実装（DNS.Bytes）による Assembler。
type ScratchDNSAssembler struct{}

var _ Assembler = (*ScratchDNSAssembler)(nil)

func (s *ScratchDNSAssembler) Fields() []FieldSpec {
	return []FieldSpec{
		{Key: "transaction_id", Label: "Transaction ID", Kind: FieldKindHex, Default: "0xaa78"},
		{Key: "flags", Label: "Flags", Kind: FieldKindHex, Default: "0x0100"},
		{Key: "questions", Label: "Questions", Kind: FieldKindHex, Default: "0x0001"},
		{Key: "answer_rrs", Label: "AnswerRRs", Kind: FieldKindHex, Default: "0x0000"},
		{Key: "authority_rrs", Label: "AuthorityRRs", Kind: FieldKindHex, Default: "0x0000"},
		{Key: "additional_rrs", Label: "AdditionalRRs", Kind: FieldKindHex, Default: "0x0000"},
		{Key: "query_domain", Label: "Queries Domain", Kind: FieldKindText, Default: "go.dev"},
		{Key: "query_type", Label: "Queries Type", Kind: FieldKindHex, Default: "0x0001"},
		{Key: "query_class", Label: "Queries Class", Kind: FieldKindHex, Default: "0x0001"},
	}
}

func (s *ScratchDNSAssembler) Assemble(values map[string]any, _ []byte) ([]byte, error) {
	// DNS は上位レイヤを持たないため payload は使わない
	dns, err := s.AssembleDNS(values)
	if err != nil {
		return nil, err
	}
	return dns.Bytes(), nil
}

// AssembleDNS は values から DNS 構造体を組み立てる。
// TUI の動的フォームが、既存の送信経路（sender の packets）へ構造体を渡すために使う。
func (s *ScratchDNSAssembler) AssembleDNS(values map[string]any) (*DNS, error) {
	dns := &DNS{Queries: &Queries{}}
	var err error
	if dns.TransactionID, err = uint16FromValue(values["transaction_id"]); err != nil {
		return nil, fmt.Errorf("transaction_id: %w", err)
	}
	if dns.Flags, err = uint16FromValue(values["flags"]); err != nil {
		return nil, fmt.Errorf("flags: %w", err)
	}
	if dns.Questions, err = uint16FromValue(values["questions"]); err != nil {
		return nil, fmt.Errorf("questions: %w", err)
	}
	if dns.AnswerRRs, err = uint16FromValue(values["answer_rrs"]); err != nil {
		return nil, fmt.Errorf("answer_rrs: %w", err)
	}
	if dns.AuthorityRRs, err = uint16FromValue(values["authority_rrs"]); err != nil {
		return nil, fmt.Errorf("authority_rrs: %w", err)
	}
	if dns.AdditionalRRs, err = uint16FromValue(values["additional_rrs"]); err != nil {
		return nil, fmt.Errorf("additional_rrs: %w", err)
	}

	domain, err := stringFromValue(values["query_domain"])
	if err != nil {
		return nil, fmt.Errorf("query_domain: %w", err)
	}
	dns.Domain(domain) // ドメイン名のラベルエンコードは既存実装に委ねる
	if dns.Queries.Typ, err = uint16FromValue(values["query_type"]); err != nil {
		return nil, fmt.Errorf("query_type: %w", err)
	}
	if dns.Queries.Class, err = uint16FromValue(values["query_class"]); err != nil {
		return nil, fmt.Errorf("query_class: %w", err)
	}
	return dns, nil
}
