package main

// https://www.infraexpert.com/study/tcpip1.html
type ipv4 struct {
	version        uint8
	ihl            uint8  // hearder length
	tos            uint8  // type of service
	totalLength    uint16 // total length
	identification uint16
	flags          uint8
	fragmentOffset uint16
	ttl            uint8
	protocol       uint8
	headerChecksum uint16
	srcAddr        uint32
	dstAddr        uint32

	options []uint8
	padding []uint8
}
