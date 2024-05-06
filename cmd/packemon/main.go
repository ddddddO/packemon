package main

import (
	"errors"
	"flag"
	"fmt"
	"strings"

	"github.com/ddddddO/packemon"
	"github.com/ddddddO/packemon/internal/debugging"
	"github.com/ddddddO/packemon/tui"
)

const DEFAULT_TARGET_NW_INTERFACE = "eth0"

func main() {
	var nwInterface string
	flag.StringVar(&nwInterface, "interface", DEFAULT_TARGET_NW_INTERFACE, "Specify name of network interface to be sent/received. Default is 'eth0'.")
	var wantSend bool
	flag.BoolVar(&wantSend, "send", false, "Monitor mode.")
	var debug bool
	flag.BoolVar(&debug, "debug", false, "Debugging mode.")
	var protocol string
	flag.StringVar(&protocol, "proto", "", "Specify either 'arp', 'icmp', 'tcp', 'dns' or 'http'.")
	flag.Parse()

	if err := run(nwInterface, wantSend, debug, protocol); err != nil {
		panic(err)
	}
}

func run(nwInterface string, wantSend bool, debug bool, protocol string) error {
	netIf, err := packemon.NewNetworkInterface(nwInterface)
	if err != nil {
		return err
	}

	// TODO: 以降要refactor
	tui.DEFAULT_MAC_DESTINATION = fmt.Sprintf("0x%s", strings.ReplaceAll(netIf.Intf.HardwareAddr.String(), ":", ""))
	tui.DEFAULT_MAC_SOURCE = tui.DEFAULT_MAC_DESTINATION
	tui.DEFAULT_ARP_SENDER_MAC = tui.DEFAULT_MAC_SOURCE

	fmt.Printf("Monitor interface: %v\n", netIf.Intf)
	ipAddr, err := netIf.Intf.Addrs()
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

	if debug {
		return debugMode(wantSend, protocol, netIf, firsthopMACAddr)
	}

	if wantSend {
		tui := tui.NewTUI(wantSend)
		return tui.Generator(netIf.Send)
	} else {
		tui := tui.NewTUI(wantSend)
		go netIf.Recieve()
		return tui.Monitor(netIf.PassiveCh)
	}
}

func debugMode(wantSend bool, protocol string, netIf *packemon.NetworkInterface, dstMacAddr [6]byte) error {
	debugNetIf := debugging.NewDebugNetworkInterface(netIf)

	if wantSend {
		switch protocol {
		case "arp":
			return debugNetIf.SendARPrequest(dstMacAddr)
		case "icmp":
			return debugNetIf.SendICMPechoRequest(dstMacAddr)
		case "tcp":
			return debugNetIf.SendTCPsyn(dstMacAddr)
		case "dns":
			return debugNetIf.SendDNSquery(dstMacAddr)
		case "http":
			return debugNetIf.SendHTTPget(dstMacAddr)
		default:
			return errors.New("not supported protocol")
		}
	}

	return debugNetIf.Recieve()
}
