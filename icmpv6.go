package packemon

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
)

// https://ja.wikipedia.org/wiki/Internet_Control_Message_Protocol_for_IPv6
// https://www.iana.org/assignments/icmpv6-parameters
const (
	ICMPv6_TYPE_DESTINATION_UNREACHABLE                         = 0x01
	ICMPv6_TYPE_TIME_EXCEEDED                                   = 0x03
	ICMPv6_TYPE_PRIVATE_EXPERIMENTATION_100                     = 0x64
	ICMPv6_TYPE_PRIVATE_EXPERIMENTATION_101                     = 0x65
	ICMPv6_TYPE_RESERVED_FOR_EXPANSION_OF_ICMPV6_ERROR_MESSAGES = 0x7f
	ICMPv6_TYPE_PACKET_TOO_BIG                                  = 0x02
	ICMPv6_TYPE_PARAMETER_PROBLEM                               = 0x04
	ICMPv6_TYPE_ECHO_REQUEST                                    = 0x80
	ICMPv6_TYPE_ECHO_REPLY                                      = 0x81
	ICMPv6_TYPE_PRIVATE_EXPERIMENTATION_200                     = 0xc8
	ICMPv6_TYPE_PRIVATE_EXPERIMENTATION_201                     = 0xc9
	ICMPv6_TYPE_ROUTER_SOLICITATION                             = 0x85
	ICMPv6_TYPE_ROUTER_ADVERTISEMENT                            = 0x86
	ICMPv6_TYPE_NEIGHBOR_SOLICITATION                           = 0x87
	ICMPv6_TYPE_NEIGHBOR_ADVERTISEMENT                          = 0x88
	ICMPv6_TYPE_REDIRECT                                        = 0x89
	ICMPv6_TYPE_SECURE_NEIGHBOR_DISCOVERY_141                   = 0x8d
	ICMPv6_TYPE_SECURE_NEIGHBOR_DISCOVERY_142                   = 0x8e
	ICMPv6_TYPE_HOME_AGENT_DISCOVERY_144                        = 0x90
	ICMPv6_TYPE_HOME_AGENT_DISCOVERY_145                        = 0x91
	ICMPv6_TYPE_MULTICAST_LISTENER_QUERY                        = 0x82
	ICMPv6_TYPE_MULTICAST_LISTENER_REPORT                       = 0x83
	ICMPv6_TYPE_MULTICAST_LISTENER_DONE                         = 0x84
	ICMPv6_TYPE_MLDv2_MULTICAST_LISTENER_REPORT                 = 0x8f
)

// Destination Unreachable /Time Exceeded / (Type 100 / 101) Private Experimentation / Reserved for expansion of ICMPv6 error messages
type ICMPv6Error struct {
	Header *ICMPHeader
	Unused uint32
	Data   []byte
}

func (i *ICMPv6Error) Bytes() []byte {
	buf := &bytes.Buffer{}
	buf.WriteByte(i.Header.Typ)
	buf.WriteByte(i.Header.Code)
	WriteUint16(buf, i.Header.Checksum)
	WriteUint32(buf, i.Unused)
	buf.Write(i.Data)
	return buf.Bytes()
}

func (i *ICMPv6Error) FieldNode() *FieldNode {
	children := []*FieldNode{
		{Name: "Type", Value: fmt.Sprintf("0x%02x", i.Header.Typ)},
		{Name: "Code", Value: fmt.Sprintf("0x%02x", i.Header.Code)},
		{Name: "Checksum", Value: fmt.Sprintf("0x%04x", i.Header.Checksum)},
		{Name: "Unused", Value: fmt.Sprintf("0x%x", i.Unused)},
	}
	if len(i.Data) > 0 {
		children = append(children, &FieldNode{
			Name:  "Data",
			Value: fmt.Sprintf("0x%x", i.Data),
		})
	}

	return &FieldNode{
		Name:     "ICMPv6",
		Children: children,
	}
}

func ParsedICMPv6Error(payload []byte) *ICMPv6Error {
	return &ICMPv6Error{
		Header: &ICMPHeader{
			Typ:      payload[0],
			Code:     payload[1],
			Checksum: binary.BigEndian.Uint16(payload[2:4]),
		},
		Unused: binary.BigEndian.Uint32(payload[4:8]),
		Data:   payload[8:],
	}
}

// Packet Too Big
type ICMPv6PacketTooBig struct {
	Header *ICMPHeader
	MTU    uint32
	Data   []byte
}

func (i *ICMPv6PacketTooBig) Bytes() []byte {
	buf := &bytes.Buffer{}
	buf.WriteByte(i.Header.Typ)
	buf.WriteByte(i.Header.Code)
	WriteUint16(buf, i.Header.Checksum)
	WriteUint32(buf, i.MTU)
	buf.Write(i.Data)
	return buf.Bytes()
}

func (i *ICMPv6PacketTooBig) FieldNode() *FieldNode {
	children := []*FieldNode{
		{Name: "Type", Value: fmt.Sprintf("0x%02x", i.Header.Typ)},
		{Name: "Code", Value: fmt.Sprintf("0x%02x", i.Header.Code)},
		{Name: "Checksum", Value: fmt.Sprintf("0x%04x", i.Header.Checksum)},
		{Name: "MTU", Value: fmt.Sprintf("%d", i.MTU)},
	}
	if len(i.Data) > 0 {
		children = append(children, &FieldNode{
			Name:  "Data",
			Value: fmt.Sprintf("0x%x", i.Data),
		})
	}

	return &FieldNode{
		Name:     "ICMPv6",
		Children: children,
	}
}

func ParsedICMPv6PacketTooBig(payload []byte) *ICMPv6PacketTooBig {
	return &ICMPv6PacketTooBig{
		Header: &ICMPHeader{
			Typ:      payload[0],
			Code:     payload[1],
			Checksum: binary.BigEndian.Uint16(payload[2:4]),
		},
		MTU:  binary.BigEndian.Uint32(payload[4:8]),
		Data: payload[8:],
	}
}

// Parameter Problem
type ICMPv6ParameterProblem struct {
	Header  *ICMPHeader
	Pointer uint32
	Data    []byte
}

func (i *ICMPv6ParameterProblem) Bytes() []byte {
	buf := &bytes.Buffer{}
	buf.WriteByte(i.Header.Typ)
	buf.WriteByte(i.Header.Code)
	WriteUint16(buf, i.Header.Checksum)
	WriteUint32(buf, i.Pointer)
	buf.Write(i.Data)
	return buf.Bytes()
}

func (i *ICMPv6ParameterProblem) FieldNode() *FieldNode {
	children := []*FieldNode{
		{Name: "Type", Value: fmt.Sprintf("0x%02x", i.Header.Typ)},
		{Name: "Code", Value: fmt.Sprintf("0x%02x", i.Header.Code)},
		{Name: "Checksum", Value: fmt.Sprintf("0x%04x", i.Header.Checksum)},
		{Name: "Pointer", Value: fmt.Sprintf("%d", i.Pointer)},
	}
	if len(i.Data) > 0 {
		children = append(children, &FieldNode{
			Name:  "Data",
			Value: fmt.Sprintf("0x%x", i.Data),
		})
	}

	return &FieldNode{
		Name:     "ICMPv6",
		Children: children,
	}
}

func ParsedICMPv6ParameterProblem(payload []byte) *ICMPv6ParameterProblem {
	return &ICMPv6ParameterProblem{
		Header: &ICMPHeader{
			Typ:      payload[0],
			Code:     payload[1],
			Checksum: binary.BigEndian.Uint16(payload[2:4]),
		},
		Pointer: binary.BigEndian.Uint32(payload[4:8]),
		Data:    payload[8:],
	}
}

// Echo Request / Echo Reply / (Type 200 / 201) Private Experimentation
type ICMPv6Echo struct {
	Header     *ICMPHeader
	Identifier uint16
	Sequence   uint16
	Data       []byte
}

func CalculateChecksumICMPv6(ipv6 *IPv6, icmpv6Data []byte) uint16 {
	buf := &bytes.Buffer{}
	buf.Write(ipv6.PseudoHeader(uint32(len(icmpv6Data))))
	buf.Write(icmpv6Data)

	b := buf.Bytes()
	csumcv := len(b) - 1 // checksum coverage
	s := uint32(0)
	for i := 0; i < csumcv; i += 2 {
		s += uint32(b[i+1])<<8 | uint32(b[i])
	}
	if csumcv&1 == 0 {
		s += uint32(b[csumcv])
	}
	s = s>>16 + s&0xffff
	s = s + s>>16

	ret := make([]byte, 2)
	binary.LittleEndian.PutUint16(ret, ^uint16(s))
	return binary.BigEndian.Uint16(ret)
}

func (i *ICMPv6Echo) Bytes() []byte {
	buf := &bytes.Buffer{}
	buf.WriteByte(i.Header.Typ)
	buf.WriteByte(i.Header.Code)
	WriteUint16(buf, i.Header.Checksum)
	WriteUint16(buf, i.Identifier)
	WriteUint16(buf, i.Sequence)
	buf.Write(i.Data)
	return buf.Bytes()
}

func (i *ICMPv6Echo) FieldNode() *FieldNode {
	children := []*FieldNode{
		{Name: "Type", Value: fmt.Sprintf("0x%02x", i.Header.Typ)},
		{Name: "Code", Value: fmt.Sprintf("0x%02x", i.Header.Code)},
		{Name: "Checksum", Value: fmt.Sprintf("0x%04x", i.Header.Checksum)},
		{Name: "Identifier", Value: fmt.Sprintf("%d", i.Identifier)},
		{Name: "Sequence", Value: fmt.Sprintf("%d", i.Sequence)},
	}
	if len(i.Data) > 0 {
		children = append(children, &FieldNode{
			Name:  "Data",
			Value: fmt.Sprintf("0x%x", i.Data),
		})
	}

	return &FieldNode{
		Name:     "ICMPv6",
		Children: children,
	}
}

func ParsedICMPv6Echo(payload []byte) *ICMPv6Echo {
	return &ICMPv6Echo{
		Header: &ICMPHeader{
			Typ:      payload[0],
			Code:     payload[1],
			Checksum: binary.BigEndian.Uint16(payload[2:4]),
		},
		Identifier: binary.BigEndian.Uint16(payload[4:6]),
		Sequence:   binary.BigEndian.Uint16(payload[6:8]),
		Data:       payload[8:],
	}
}

// TODO: Redirect / Secure Neighbor Discovery / Home Agent Discovery はこの構造体でカバー不可. monitorのパースでこれ使っちゃってるの直す。READMEも
// Router Solicitation / Neighbor Solicitation / Neighbor Advertisement
type ICMPv6NeighborDiscovery struct {
	Header        *ICMPHeader
	ReservedFlags uint32
	TargetAddress [16]byte
	Options       []byte
}

func (i *ICMPv6NeighborDiscovery) Bytes() []byte {
	buf := &bytes.Buffer{}
	buf.WriteByte(i.Header.Typ)
	buf.WriteByte(i.Header.Code)
	WriteUint16(buf, i.Header.Checksum)
	WriteUint32(buf, i.ReservedFlags)
	buf.Write(i.TargetAddress[:])
	buf.Write(i.Options)
	return buf.Bytes()
}

func (i *ICMPv6NeighborDiscovery) FieldNode() *FieldNode {
	children := []*FieldNode{
		{Name: "Type", Value: fmt.Sprintf("0x%02x", i.Header.Typ)},
		{Name: "Code", Value: fmt.Sprintf("0x%02x", i.Header.Code)},
		{Name: "Checksum", Value: fmt.Sprintf("0x%04x", i.Header.Checksum)},
		{Name: "ReservedFlags", Value: fmt.Sprintf("0x%08x", i.ReservedFlags)},
		{Name: "TargetAddress", Value: net.IP(i.TargetAddress[:]).String()},
	}
	if len(i.Options) > 0 {
		children = append(children, &FieldNode{
			Name:  "Options",
			Value: fmt.Sprintf("0x%x", i.Options),
		})
	}

	return &FieldNode{
		Name:     "ICMPv6",
		Children: children,
	}
}

func ParsedICMPv6NeighborDiscovery(payload []byte) *ICMPv6NeighborDiscovery {
	return &ICMPv6NeighborDiscovery{
		Header: &ICMPHeader{
			Typ:      payload[0],
			Code:     payload[1],
			Checksum: binary.BigEndian.Uint16(payload[2:4]),
		},
		ReservedFlags: binary.BigEndian.Uint32(payload[4:8]),
		TargetAddress: [16]byte(payload[8:24]),
		Options:       payload[24:],
	}
}

// Router Advertisement
type ICMPv6RouterAdvertisement struct {
	Header          *ICMPHeader
	CurrentHopLimit uint8
	Flags           uint8
	RouterLifetime  uint16
	ReachableTime   uint32
	RetransTimer    uint32
	Options         []byte
}

func (i *ICMPv6RouterAdvertisement) Bytes() []byte {
	buf := &bytes.Buffer{}
	buf.WriteByte(i.Header.Typ)
	buf.WriteByte(i.Header.Code)
	WriteUint16(buf, i.Header.Checksum)
	buf.WriteByte(i.CurrentHopLimit)
	buf.WriteByte(i.Flags)
	WriteUint16(buf, i.RouterLifetime)
	WriteUint32(buf, i.ReachableTime)
	WriteUint32(buf, i.RetransTimer)
	buf.Write(i.Options)
	return buf.Bytes()
}

func (i *ICMPv6RouterAdvertisement) FieldNode() *FieldNode {
	children := []*FieldNode{
		{Name: "Type", Value: fmt.Sprintf("0x%02x", i.Header.Typ)},
		{Name: "Code", Value: fmt.Sprintf("0x%02x", i.Header.Code)},
		{Name: "Checksum", Value: fmt.Sprintf("0x%04x", i.Header.Checksum)},
		{Name: "CurrentHopLimit", Value: fmt.Sprintf("%d", i.CurrentHopLimit)},
		{Name: "Flags", Value: fmt.Sprintf("0x%02x", i.Flags)},
		{Name: "RouterLifetime", Value: fmt.Sprintf("%d", i.RouterLifetime)},
		{Name: "ReachableTime", Value: fmt.Sprintf("%d", i.ReachableTime)},
		{Name: "RetransTimer", Value: fmt.Sprintf("%d", i.RetransTimer)},
	}
	if len(i.Options) > 0 {
		children = append(children, &FieldNode{
			Name:  "Options",
			Value: fmt.Sprintf("0x%x", i.Options),
		})
	}

	return &FieldNode{
		Name:     "ICMPv6",
		Children: children,
	}
}

func ParsedICMPv6RouterAdvertisement(payload []byte) *ICMPv6RouterAdvertisement {
	return &ICMPv6RouterAdvertisement{
		Header: &ICMPHeader{
			Typ:      payload[0],
			Code:     payload[1],
			Checksum: binary.BigEndian.Uint16(payload[2:4]),
		},
		CurrentHopLimit: payload[4],
		Flags:           payload[5],
		RouterLifetime:  binary.BigEndian.Uint16(payload[6:8]),
		ReachableTime:   binary.BigEndian.Uint32(payload[8:12]),
		RetransTimer:    binary.BigEndian.Uint32(payload[12:16]),
		Options:         payload[16:],
	}
}

// Multicast Listener Discovery (Type 130, 131, 132)
type ICMPv6MulticastListenerDiscovery struct {
	Header           *ICMPHeader
	MaxResponseDelay uint16
	Reserved         uint16
	MulticastAddress [16]byte
}

func (i *ICMPv6MulticastListenerDiscovery) Bytes() []byte {
	buf := &bytes.Buffer{}
	buf.WriteByte(i.Header.Typ)
	buf.WriteByte(i.Header.Code)
	WriteUint16(buf, i.Header.Checksum)
	WriteUint16(buf, i.MaxResponseDelay)
	WriteUint16(buf, i.Reserved)
	buf.Write(i.MulticastAddress[:])
	return buf.Bytes()
}

func (i *ICMPv6MulticastListenerDiscovery) FieldNode() *FieldNode {
	children := []*FieldNode{
		{Name: "Type", Value: fmt.Sprintf("0x%02x", i.Header.Typ)},
		{Name: "Code", Value: fmt.Sprintf("0x%02x", i.Header.Code)},
		{Name: "Checksum", Value: fmt.Sprintf("0x%04x", i.Header.Checksum)},
		{Name: "MaxResponseDelay", Value: fmt.Sprintf("%d", i.MaxResponseDelay)},
		{Name: "Reserved", Value: fmt.Sprintf("0x%04x", i.Reserved)},
		{Name: "MulticastAddress", Value: net.IP(i.MulticastAddress[:]).String()},
	}

	return &FieldNode{
		Name:     "ICMPv6",
		Children: children,
	}
}

func ParsedICMPv6MulticastListenerDiscovery(payload []byte) *ICMPv6MulticastListenerDiscovery {
	return &ICMPv6MulticastListenerDiscovery{
		Header: &ICMPHeader{
			Typ:      payload[0],
			Code:     payload[1],
			Checksum: binary.BigEndian.Uint16(payload[2:4]),
		},
		MaxResponseDelay: binary.BigEndian.Uint16(payload[4:6]),
		Reserved:         binary.BigEndian.Uint16(payload[6:8]),
		MulticastAddress: [16]byte(payload[8:24]),
	}
}

type ScratchICMPv6EchoAssembler struct{}

var _ Assembler = (*ScratchICMPv6EchoAssembler)(nil)

func (s *ScratchICMPv6EchoAssembler) Fields() []FieldSpec {
	return []FieldSpec{
		{Key: "type", Label: "Type", Kind: FieldKindHex, Default: "0x80"},
		{Key: "code", Label: "Code", Kind: FieldKindHex, Default: "0x00"},
		{Key: "checksum", Label: "Checksum", Kind: FieldKindHex, Default: "0x0000"},
		{Key: "calc_checksum", Label: "Automatically calculate checksum ?", Kind: FieldKindCheckbox, Default: "true"},
		{Key: "identifier", Label: "Identifier", Kind: FieldKindHex, Default: "0x34a1"},
		{Key: "sequence", Label: "Sequence", Kind: FieldKindHex, Default: "0x0001"},
		{Key: "data", Label: "Data", Kind: FieldKindHex, Default: ""},
	}
}

func (s *ScratchICMPv6EchoAssembler) Assemble(values map[string]any, payload []byte) ([]byte, error) {
	icmpv6, err := s.AssembleICMPv6Echo(values)
	if err != nil {
		return nil, err
	}

	if calc, err := boolFromValue(values["calc_checksum"]); err != nil {
		return nil, fmt.Errorf("calc_checksum: %w", err)
	} else if calc {
		icmpv6.Header.Checksum = 0x0
	}

	return icmpv6.Bytes(), nil
}

func (s *ScratchICMPv6EchoAssembler) AssembleICMPv6Echo(values map[string]any) (*ICMPv6Echo, error) {
	icmpv6 := &ICMPv6Echo{Header: &ICMPHeader{}}
	var err error
	if icmpv6.Header.Typ, err = uint8FromValue(values["type"]); err != nil {
		return nil, fmt.Errorf("type: %w", err)
	}
	if icmpv6.Header.Code, err = uint8FromValue(values["code"]); err != nil {
		return nil, fmt.Errorf("code: %w", err)
	}
	if icmpv6.Header.Checksum, err = uint16FromValue(values["checksum"]); err != nil {
		return nil, fmt.Errorf("checksum: %w", err)
	}
	if icmpv6.Identifier, err = uint16FromValue(values["identifier"]); err != nil {
		return nil, fmt.Errorf("identifier: %w", err)
	}
	if icmpv6.Sequence, err = uint16FromValue(values["sequence"]); err != nil {
		return nil, fmt.Errorf("sequence: %w", err)
	}
	if icmpv6.Data, err = bytesFromValue(values["data"]); err != nil {
		return nil, fmt.Errorf("data: %w", err)
	}
	return icmpv6, nil
}

type ScratchICMPv6NeighborDiscoveryAssembler struct{}

var _ Assembler = (*ScratchICMPv6NeighborDiscoveryAssembler)(nil)

func (s *ScratchICMPv6NeighborDiscoveryAssembler) Fields() []FieldSpec {
	return []FieldSpec{
		{Key: "type", Label: "Type", Kind: FieldKindHex, Default: "0x87"},
		{Key: "code", Label: "Code", Kind: FieldKindHex, Default: "0x00"},
		{Key: "checksum", Label: "Checksum", Kind: FieldKindHex, Default: "0x0000"},
		{Key: "calc_checksum", Label: "Automatically calculate checksum ?", Kind: FieldKindCheckbox, Default: "true"},
		{Key: "reserved_flags", Label: "Reserved Flags", Kind: FieldKindHex, Default: "0x00000000"},
		{Key: "target_address", Label: "Target Address", Kind: FieldKindText, Default: ""},
		{Key: "options", Label: "Options", Kind: FieldKindHex, Default: ""},
	}
}

func (s *ScratchICMPv6NeighborDiscoveryAssembler) Assemble(values map[string]any, payload []byte) ([]byte, error) {
	icmpv6, err := s.AssembleICMPv6NeighborDiscovery(values)
	if err != nil {
		return nil, err
	}

	if calc, err := boolFromValue(values["calc_checksum"]); err != nil {
		return nil, fmt.Errorf("calc_checksum: %w", err)
	} else if calc {
		icmpv6.Header.Checksum = 0x0
	}

	return icmpv6.Bytes(), nil
}

func (s *ScratchICMPv6NeighborDiscoveryAssembler) AssembleICMPv6NeighborDiscovery(values map[string]any) (*ICMPv6NeighborDiscovery, error) {
	icmpv6 := &ICMPv6NeighborDiscovery{Header: &ICMPHeader{}}
	var err error
	if icmpv6.Header.Typ, err = uint8FromValue(values["type"]); err != nil {
		return nil, fmt.Errorf("type: %w", err)
	}
	if icmpv6.Header.Code, err = uint8FromValue(values["code"]); err != nil {
		return nil, fmt.Errorf("code: %w", err)
	}
	if icmpv6.Header.Checksum, err = uint16FromValue(values["checksum"]); err != nil {
		return nil, fmt.Errorf("checksum: %w", err)
	}
	if icmpv6.ReservedFlags, err = uint32FromValue(values["reserved_flags"]); err != nil {
		return nil, fmt.Errorf("reserved_flags: %w", err)
	}
	targetAddress, err := ipv6AddrFromValue(values["target_address"])
	if err != nil {
		return nil, fmt.Errorf("target_address: %w", err)
	}
	copy(icmpv6.TargetAddress[:], targetAddress)
	if icmpv6.Options, err = bytesFromValue(values["options"]); err != nil {
		return nil, fmt.Errorf("options: %w", err)
	}
	return icmpv6, nil
}
