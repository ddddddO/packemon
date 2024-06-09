package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/ddddddO/packemon"
	"github.com/ddddddO/packemon/internal/debugging"
	"github.com/ddddddO/packemon/internal/tui"
	"github.com/vishvananda/netlink"

	"golang.org/x/sys/unix"
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

	if wantSend {
		// Generator で3way handshake する際に、カーネルが自動でRSTパケットを送ってたため、ドロップするため
		ebpfProg, qdisc, err := prepareDropingRSTPacket(nwInterface)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		defer func() {
			ebpfProg.Close()
			// 以下で消しておかないと、再起動やtcコマンド使わない限り、RSTパケットがカーネルから送信されない状態になる
			if err := netlink.QdiscDel(qdisc); err != nil {
				log.Printf("Failed to QdiscDel. Please PC reboot... Error: %s\n", err)
			}
		}()
	}

	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt)
	// 以下でもctl-cしないといけない
	go run(stop, nwInterface, wantSend, debug, protocol)
	<-stop
	log.Print("Received signal, exiting...")
}

func prepareDropingRSTPacket(nwInterface string) (*egress_packetObjects, *netlink.GenericQdisc, error) {
	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, nil, fmt.Errorf("removing memlock: %w", err)
	}

	// Load the compiled eBPF ELF and load it into the kernel.
	var objs egress_packetObjects
	if err := loadEgress_packetObjects(&objs, nil); err != nil {
		return nil, nil, fmt.Errorf("loading eBPF objects: %w", err)
	}

	qdisc, err := attachFilter(nwInterface, objs.egress_packetPrograms.ControlEgress)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to attach: %w", err)
	}

	return &objs, qdisc, nil
}

// https://github.com/fedepaol/tc-return/blob/main/main.go
func attachFilter(attachTo string, program *ebpf.Program) (*netlink.GenericQdisc, error) {
	devID, err := net.InterfaceByName(attachTo)
	if err != nil {
		return nil, fmt.Errorf("could not get interface ID: %w", err)
	}

	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: devID.Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}

	err = netlink.QdiscReplace(qdisc)
	if err != nil {
		return nil, fmt.Errorf("could not get replace qdisc: %w", err)
	}

	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: devID.Index,
			Parent:    netlink.HANDLE_MIN_EGRESS,
			Handle:    1,
			Protocol:  unix.ETH_P_ALL,
		},
		Fd:           program.FD(),
		Name:         program.String(),
		DirectAction: true,
	}

	if err := netlink.FilterReplace(filter); err != nil {
		return nil, fmt.Errorf("failed to replace tc filter: %w", err)
	}

	return qdisc, nil
}

func run(stop <-chan os.Signal, nwInterface string, wantSend bool, debug bool, protocol string) error {
	// packemonを終了した後でsignal飛ばしてもらって終了させてもらう、一旦
	fmt.Println("Terminate packemon <Monitor> with ctl-c.")

	netIf, err := packemon.NewNetworkInterface(nwInterface)
	if err != nil {
		return err
	}
	defer netIf.Close()

	tui.DEFAULT_MAC_SOURCE = fmt.Sprintf("0x%s", strings.ReplaceAll(netIf.Intf.HardwareAddr.String(), ":", ""))
	tui.DEFAULT_ARP_SENDER_MAC = tui.DEFAULT_MAC_SOURCE

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
			firsthopMACAddr := [6]byte{0x00, 0x15, 0x5d, 0x64, 0xb2, 0x11}
			return debugMode(wantSend, protocol, netIf, firsthopMACAddr)
		}

		// Monitor の debug は本チャンの networkinterface.go 使うようにする
		go netIf.Recieve(stop)
		return debugPrint(stop, netIf.PassiveCh)
	}

	if wantSend {
		tui.DEFAULT_NW_INTERFACE = nwInterface
		tui := tui.NewTUI(wantSend)
		return tui.Generator(stop, netIf.Send)
	} else {
		tui := tui.NewTUI(wantSend)
		go netIf.Recieve(stop)
		return tui.Monitor(netIf.PassiveCh)
	}
}

func debugPrint(stop <-chan os.Signal, passive <-chan *packemon.Passive) error {
	for {
		select {
		case <-stop:
			return nil
		case p := <-passive:
			if p.HighLayerProto() == "IPv6" {
				fmt.Println("Passive!")
				fmt.Printf("%x\n", p.IPv6)
			}
		}
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
