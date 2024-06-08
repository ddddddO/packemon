package main

import (
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

	tui.DEFAULT_MAC_SOURCE = fmt.Sprintf("0x%s", strings.ReplaceAll(netIf.Intf.HardwareAddr.String(), ":", ""))
	tui.DEFAULT_ARP_SENDER_MAC = tui.DEFAULT_MAC_SOURCE

	fmt.Printf("Monitor interface: %v\n", netIf.Intf)

	ipAddr, err := netIf.Intf.Addrs()
	if err != nil {
		return err
	}
	tui.DEFAULT_IP_SOURCE = strings.Split(ipAddr[0].String(), "/")[0]
	tui.DEFAULT_ARP_SENDER_IP = tui.DEFAULT_IP_SOURCE

	if debug {
		if wantSend {
			// if protocol == "tcp-3way-http" {
			// 	dstIPAddr := make([]byte, 4)
			// 	binary.BigEndian.PutUint32(dstIPAddr, 0xc0a80a6e) // 192.168.10.110
			// 	var dstPort uint16 = 0x0050                       // 80
			// 	httpGet := packemon.NewHTTP()
			// 	return packemon.EstablishConnectionAndSendPayload(nwInterface, dstIPAddr, dstPort, httpGet.Bytes())
			// }

			// PC再起動とかでdstのMACアドレス変わるみたい。以下で調べてdst正しいのにする
			// $ ip route
			// $ arp xxx.xx.xxx.1
			firsthopMACAddr := [6]byte{0x00, 0x15, 0x5d, 0xc2, 0x6c, 0xb4}
			return debugMode(wantSend, protocol, netIf, firsthopMACAddr)
		}

		// Monitor の debug は本チャンの networkinterface.go 使うようにする
		go netIf.Recieve()
		return debugPrint(netIf.PassiveCh)
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

func debugPrint(passive <-chan *packemon.Passive) error {
	for p := range passive {
		if p.HighLayerProto() == "IPv6" {
			fmt.Println("Passive!")
			fmt.Printf("%x\n", p.IPv6)
		}

	}

	return nil
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
		case "tcp-3way-http":
			return debugNetIf.SendTCP3wayhandshake(dstMacAddr)
		case "http":
			var srcPort uint16 = 0x9e98
			var dstPort uint16 = 0x0050       // 80
			var srcIPAddr uint32 = 0xac184fcf // 172.23.242.78
			var dstIPAddr uint32 = 0xc0a80a6e // raspberry pi
			return debugNetIf.SendHTTPget(srcPort, dstPort, srcIPAddr, dstIPAddr, dstMacAddr, 0x00000000, 0x00000000)
		default:
			return errors.New("not supported protocol")
		}
	}

	return debugNetIf.Recieve()
}
