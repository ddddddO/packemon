package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/ddddddO/packemon"
	"github.com/ddddddO/packemon/internal/debugging"
	"github.com/ddddddO/packemon/internal/tui"
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
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(nwInterface string, wantSend bool, debug bool, protocol string) error {
	netIf, err := packemon.NewNetworkInterface(nwInterface)
	if err != nil {
		return err
	}
	defer netIf.Close()

	// TODO: 以降要refactor
	tui.DEFAULT_MAC_DESTINATION = "0x00155dfbbf3a"
	tui.DEFAULT_MAC_SOURCE = fmt.Sprintf("0x%s", strings.ReplaceAll(netIf.Intf.HardwareAddr.String(), ":", ""))
	tui.DEFAULT_ARP_SENDER_MAC = tui.DEFAULT_MAC_SOURCE

	fmt.Printf("Monitor interface: %v\n", netIf.Intf)
	ipAddr, err := netIf.Intf.Addrs()
	if err != nil {
		return err
	}
	tui.DEFAULT_IP_SOURCE = strings.Split(ipAddr[0].String(), "/")[0]
	// tui.DEFAULT_IP_DESTINATION = tui.DEFAULT_IP_SOURCE
	tui.DEFAULT_IP_DESTINATION = "192.168.10.110" // raspbbery pi
	tui.DEFAULT_ARP_SENDER_IP = tui.DEFAULT_IP_SOURCE
	tui.DEFAULT_ARP_TARGET_IP = tui.DEFAULT_ARP_SENDER_IP

	if debug {
		if wantSend && protocol == "tcp-3way-http" {
			dstIPAddr := make([]byte, 4)
			binary.BigEndian.PutUint32(dstIPAddr, 0xc0a80a6e) // 192.168.10.110
			var dstPort uint16 = 0x0050                       // 80
			httpGet := packemon.NewHTTP()
			return packemon.EstablishConnectionAndSendPayload(nwInterface, dstIPAddr, dstPort, httpGet.Bytes())
		}

		// PC再起動とかでdstのMACアドレス変わるみたい。以下で調べてdst正しいのにする
		// $ ip route
		// $ arp xxx.xx.xxx.1
		firsthopMACAddr := [6]byte{0x00, 0x15, 0x5d, 0x8c, 0xc2, 0x6b}
		return debugMode(wantSend, protocol, netIf, firsthopMACAddr)
	}

	if wantSend {
		tui.DEFAULT_NW_INTERFACE = nwInterface
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
	defer debugNetIf.Close()

	if wantSend {
		switch protocol {
		case "arp":
			return debugNetIf.SendARPrequest()
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
