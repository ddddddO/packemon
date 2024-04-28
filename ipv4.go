package main

// https://www.infraexpert.com/study/tcpip1.html
type ipv4 struct {
	version        uint8  // 4bit
	ihl            uint8  // 4bit. hearder length
	tos            uint8  // 8bit. type of service
	totalLength    uint16 // 16bit. total length
	identification uint16 // 16bit
	flags          uint8  // 3bit
	fragmentOffset uint16 // 13bit
	ttl            uint8  // 8bit
	protocol       uint8  // 8bit
	headerChecksum uint16 // 16bit
	srcAddr        uint32 // 32bit
	dstAddr        uint32 // 32bit

	options []uint8
	padding []uint8
}
