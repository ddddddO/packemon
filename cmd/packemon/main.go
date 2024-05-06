package main

import (
	"flag"
	"fmt"
	"strings"

	"github.com/ddddddO/packemon"
	"github.com/ddddddO/packemon/tui"
)

const DEFAULT_TARGET_NW_INTERFACE = "eth0"

func main() {
	var nwInterface string
	flag.StringVar(&nwInterface, "interface", DEFAULT_TARGET_NW_INTERFACE, "Specify name of network interface to be sent/received. Default is 'eth0'.")
	var wantSend bool
	flag.BoolVar(&wantSend, "send", false, "Monitor mode.")
	var protocol string
	flag.StringVar(&protocol, "proto", "", "Specify either 'arp', 'icmp', 'tcp', 'dns' or 'http'.")
	flag.Parse()

	if err := run(nwInterface, wantSend, protocol); err != nil {
		panic(err)
	}
}

func run(nwInterface string, wantSend bool, protocol string) error {
	netIF, err := packemon.NewNetworkInterface(nwInterface)
	if err != nil {
		return err
	}

	fmt.Println("AAAAA")
	fmt.Println(nwInterface)
	fmt.Println(netIF.IPAdder)
	fmt.Println(netIF.Intf.HardwareAddr)

	// TODO: 以降要refactor
	tui.DEFAULT_MAC_DESTINATION = fmt.Sprintf("0x%s", strings.ReplaceAll(netIF.Intf.HardwareAddr.String(), ":", ""))
	tui.DEFAULT_MAC_SOURCE = tui.DEFAULT_MAC_DESTINATION
	tui.DEFAULT_ARP_SENDER_MAC = tui.DEFAULT_MAC_SOURCE

	fmt.Printf("Monitor interface: %v\n", netIF.Intf)
	ipAddr, err := netIF.Intf.Addrs()
	if err != nil {
		return err
	}
	tui.DEFAULT_IP_SOURCE = strings.Split(ipAddr[0].String(), "/")[0]
	tui.DEFAULT_IP_DESTINATION = tui.DEFAULT_IP_SOURCE
	tui.DEFAULT_ARP_SENDER_IP = tui.DEFAULT_IP_SOURCE
	tui.DEFAULT_ARP_TARGET_IP = tui.DEFAULT_ARP_SENDER_IP

	// PC再起動とかでdstのMACアドレス変わるみたい。以下で調べてdst正しいのにする
	// $ ip route
	// $ arp xxx.xx.xxx.1
	firsthopMACAddr := [6]byte{0x01, 0x00, 0x5e, 0x7f, 0xff, 0xfa}

	if wantSend {
		switch protocol {
		case "arp":
			return netIF.SendARPrequest(firsthopMACAddr)
		case "icmp":
			return netIF.SendICMPechoRequest(firsthopMACAddr)
		case "tcp":
			return netIF.SendTCPsyn(firsthopMACAddr)
		case "dns":
			return netIF.SendDNSquery(firsthopMACAddr)
		case "http":
			return netIF.SendHTTPget(firsthopMACAddr)
		default:
			tui := tui.NewTUI(wantSend)
			return tui.Generator(netIF.Send)
		}
	} else {
		tui := tui.NewTUI(wantSend)
		go netIF.Recieve()
		return tui.Monitor(netIF.PassiveCh)
	}
}
