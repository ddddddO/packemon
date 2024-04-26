package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

type ethernetFrame struct {
	header *ethernetHeader
	data   []byte
}

func (ef *ethernetFrame) toBytes() []byte {
	var buf bytes.Buffer

	var dstByte []byte
	for _, b := range ef.header.dst {
		dstByte = append(dstByte, b)
	}
	buf.Write(dstByte)

	var srcByte []byte
	for _, b := range ef.header.src {
		srcByte = append(srcByte, b)
	}
	buf.Write(srcByte)

	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, ef.header.typ)
	buf.Write(b)

	buf.Write(ef.data)

	return buf.Bytes()
}

type hardwareAddr [6]uint8

type ethernetHeader struct {
	dst hardwareAddr
	src hardwareAddr
	typ uint16
}

const ETHER_TYPE_IP uint16 = 0x0800
const ETHER_TYPE_ARP uint16 = 0x0806

func main() {
	interfaces, err := net.Interfaces()
	if err != nil {
		panic(err)
	}

	fmt.Println("Interfaces")

	var intf net.Interface
	for i := range interfaces {
		fmt.Println(interfaces[i])

		if interfaces[i].Name == "eth0" {
			intf = interfaces[i]
		}
	}

	// fmt.Println(intf)
	fmt.Println(unix.ETH_P_ALL)
	fmt.Println(hton(unix.ETH_P_ALL))

	sock, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(hton(unix.ETH_P_ALL)))
	if err != nil {
		panic(err)
	}

	addr := unix.SockaddrLinklayer{
		Protocol: hton(unix.ETH_P_ALL),
		Ifindex:  intf.Index,
	}

	if err := unix.Bind(sock, &addr); err != nil {
		panic(err)
	}

	src := [6]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab}
	frame := &ethernetFrame{
		header: &ethernetHeader{
			dst: hardwareAddr(intf.HardwareAddr),
			// src: hardwareAddr(intf.HardwareAddr),
			src: src,
			typ: ETHER_TYPE_ARP,
		},
		data: []byte("Yeah!!!!!"),
	}

	packet := frame.toBytes()
	if err := unix.Sendto(sock, packet, 0, &addr); err != nil {
		panic(err)
	}
}

func hton(i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
}
