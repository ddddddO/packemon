package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/ddddddO/packemon"
	"github.com/ddddddO/packemon/internal/debugging"
	"github.com/ddddddO/packemon/internal/tui"
	"github.com/ddddddO/packemon/internal/tui/generator"
	"github.com/ddddddO/packemon/internal/tui/monitor"
	tc "github.com/ddddddO/packemon/tc_program"
)

const DEFAULT_TARGET_NW_INTERFACE = "eth0"

// d: dest mac, s: src mac, t: type, p: protocol, D: dest ip, S: src ip
const DEFAULT_MONITOR_COLUMNS = "dstpDS"
const DEFAULT_MONITOR_LIMIT = 1000

const METAMON = "\n" +
	"⌒丶、＿ノ⌒丶、＿ノ⌒丶、＿ノ⌒丶、＿ノ⌒丶、＿ノ⌒丶、＿ノ" + "\n" +
	"                      ○" + "\n" +
	"                     о" + "\n" +
	"                    ｡" + "\n" +
	"\n" +
	"                   ,､-､_  ＿_" + "\n" +
	" 　　　　,､-―､_,､'´　　　￣　　`ヽ," + "\n" +
	" 　　　/　　　　　　 ・　　　 ．　　　ｌ、" + "\n" +
	" 　　　ｌ,　　　　　　 ヾニニつ　　　　`ヽ、" + "\n" +
	" 　　　 |　　　　　　　　　　　　　　　　　 `ヽ," + "\n" +
	" 　　　 ﾉ　　　　　　　　　　　　　　　　　　ノ" + "\n" +
	" 　　 /::::　　　　　　　　　　　　　　　　　/" + "\n" +
	" 　／:::::::　　　　　　　　　　　　　　　　..::l、" + "\n" +
	" /::::::::::::::::::......:::::::.　　　　　　　............::::::::::`l," + "\n" +
	" l::::::::::::::::::::::::::::::::::::......　　　....:::::::::::::::::::::::::::::`l," + "\n" +
	" ヽ,:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::ﾉ" + "\n" +
	" 　　￣￣``ヽ､_:::::::::::::::::::::::,､-―´￣`ヽ､,､-'" + "\n" +
	" 　　　　　　　　 `ヽ―-―'´"

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s\n", os.Args[0])
		flag.PrintDefaults()
		fmt.Fprintln(os.Stderr, METAMON)
	}

	// TODO: そろそろサブコマンド化したい
	var nwInterface string
	flag.StringVar(&nwInterface, "interface", DEFAULT_TARGET_NW_INTERFACE, "Specify name of network interface to be sent/received. Default is 'eth0'.")
	var wantInterfaces bool
	flag.BoolVar(&wantInterfaces, "interfaces", false, "Check the list of interfaces.")
	var columns string
	flag.StringVar(&columns, "columns", DEFAULT_MONITOR_COLUMNS, fmt.Sprintf("Specify columns to be displayed in monitor mode. Default is '%s' .", DEFAULT_MONITOR_COLUMNS))
	var limit int
	flag.IntVar(&limit, "limit", DEFAULT_MONITOR_LIMIT, fmt.Sprintf("Limits the list of packets that can be displayed on monitor mode. Default is '%d'; if less than 0 is specified, no limit.", DEFAULT_MONITOR_LIMIT))
	var wantSend bool
	flag.BoolVar(&wantSend, "send", false, "Generator mode. Default is 'Monitor mode'.")
	var debug bool
	flag.BoolVar(&debug, "debug", false, "Debugging mode.")
	var protocol string
	flag.StringVar(&protocol, "proto", "", "Specify either 'arp', 'icmp', 'tcp', 'dns' or 'http'.")

	flag.Parse()

	if wantInterfaces {
		if err := showInterfaces(); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
		return
	}

	var ingressMap, egressMap *ebpf.Map
	if wantSend {
		ebpfObjs, err := tc.InitializeTCProgram()
		if err != nil {
			// error出力するが、処理は進める
			fmt.Fprintln(os.Stderr, err)
		}

		if ebpfObjs != nil {
			qdisc, err := tc.AddClsactQdisc(nwInterface)
			if err != nil {
				// error出力するが、処理は進める
				fmt.Fprintln(os.Stderr, err)
			}

			// Generator で TCP 3way handshake する際に、カーネルが自動で RST パケットを送っており、それをドロップするため
			filterEgress, err := tc.PrepareDropingRSTPacket(nwInterface, ebpfObjs)
			if err != nil {
				// error出力するが、処理は進める
				fmt.Fprintln(os.Stderr, err)
			}
			filterIngress, err := tc.PrepareAnalyzingIngressPackets(nwInterface, ebpfObjs)
			if err != nil {
				// error出力するが、処理は進める
				fmt.Fprintln(os.Stderr, err)
			}
			ingressMap = ebpfObjs.PktIngressCount
			egressMap = ebpfObjs.PktEgressCount
			defer func() {
				if err := tc.Close(ebpfObjs, qdisc, filterEgress, filterIngress); err != nil {
					fmt.Fprintln(os.Stderr, err)
				}
			}()
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	for i := range columns {
		if !strings.Contains(DEFAULT_MONITOR_COLUMNS, string(columns[i])) {
			fmt.Fprintf(os.Stderr, "Contains unsupported columns: %s\n", string(columns[i]))
			return
		}
	}

	if err := run(ctx, columns, limit, nwInterface, wantSend, debug, protocol, ingressMap, egressMap); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
}

// TODO: テーブル形式で出力してくれるライブラリ使ってもいいかも
func showInterfaces() error {
	interfaceDevices, err := packemon.NewInterfaceDevices()
	if err != nil {
		return fmt.Errorf("failed to NewInterfaceDevices: %w", err)
	}

	splitter := func() {
		fmt.Println("--------------------------------------")
	}
	for _, interfaceDevice := range interfaceDevices {
		splitter()
		fmt.Printf("Interface name : %s\n", interfaceDevice.InterfaceName)
		fmt.Printf("Device name    : %s\n", interfaceDevice.DeviceName)
		fmt.Printf("Description    : %s\n", interfaceDevice.Description)
		fmt.Printf("MAC address    : %s\n", interfaceDevice.MacAddr)

		fmt.Printf("IP address     : \n")
		for _, ipAddr := range interfaceDevice.IPAddrs {
			fmt.Printf("\t%s\n", ipAddr)
		}
	}

	return nil
}

func run(ctx context.Context, columns string, limit int, nwInterface string, wantSend bool, debug bool, protocol string, ingressMap *ebpf.Map, egressMap *ebpf.Map) error {
	netIf, err := packemon.NewNetworkInterface(nwInterface)
	if err != nil {
		return err
	}
	defer netIf.Close()

	if len(nwInterface) != 0 {
		generator.DEFAULT_NW_INTERFACE = nwInterface
	}
	generator.DEFAULT_MAC_SOURCE = fmt.Sprintf("0x%s", strings.ReplaceAll(netIf.Intf.HardwareAddr.String(), ":", ""))
	generator.DEFAULT_ARP_SENDER_MAC = generator.DEFAULT_MAC_SOURCE

	ipAddrs, err := netIf.Intf.Addrs()
	if err != nil {
		return err
	}

	// TODO: ちょっとここちゃんとした方が良さそう
	for _, ipAddr := range ipAddrs {
		// ipv6
		if strings.Contains(ipAddr.String(), ":") {
			if len(generator.DEFAULT_IPv6_SOURCE) == 0 {
				// 一旦、最初に見つかったipv6アドレスを設定する
				generator.DEFAULT_IPv6_SOURCE = strings.Split(ipAddr.String(), "/")[0]
				continue
			}
			continue
		}

		// ipv4
		if len(generator.DEFAULT_IP_SOURCE) == 0 {
			// 一旦、最初に見つかったipv4アドレスを設定する
			generator.DEFAULT_IP_SOURCE = strings.Split(ipAddr.String(), "/")[0]
			generator.DEFAULT_ARP_SENDER_IP = generator.DEFAULT_IP_SOURCE
			continue
		}
	}

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
			rawDefaultRouteMAC, err := packemon.GetDefaultRouteMAC()
			if err != nil {
				return err
			}
			firsthopMACAddr, err := packemon.StrHexToBytes(fmt.Sprintf("0x%s", strings.ReplaceAll(rawDefaultRouteMAC, ":", "")))
			if err != nil {
				return err
			}

			return debugMode(wantSend, protocol, netIf, packemon.HardwareAddr(firsthopMACAddr))
		}

		// Monitor の debug は本チャンの networkinterface.go 使うようにする
		go netIf.Recieve(ctx)
		return debugPrint(ctx, netIf.PassiveCh)
	}

	var packemonTUI tui.TUI = monitor.New(netIf, columns, limit)
	if wantSend {
		packemonTUI = generator.New(netIf, ingressMap, egressMap)
	}
	return packemonTUI.Run(ctx)
}

func debugPrint(ctx context.Context, passive <-chan *packemon.Passive) error {
	for {
		select {
		case <-ctx.Done():
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
		case "tcp-tls-handshake":
			return debugNetIf.SendTCP3wayAndTLShandshake(dstMacAddr)
		case "https-get":
			return debugNetIf.SendHTTPSGetAfterTCP3wayAndTLShandshake(dstMacAddr)
		case "http":
			var srcPort uint16 = 0x9e98
			var dstPort uint16 = 0x0050       // 80
			var srcIPAddr uint32 = 0xac184fcf // 172.23.242.78
			var dstIPAddr uint32 = 0xc0a80a6e // raspberry pi
			return debugNetIf.SendHTTPget(srcPort, dstPort, srcIPAddr, dstIPAddr, dstMacAddr, 0x00000000, 0x00000000)
		// case "bgp": // github.com/ddddddO/packemon/cmd/debugging/bgp/main.go で試してる
		// 	return debugNetIf.FlowBGP()
		default:
			return errors.New("not supported protocol")
		}
	}

	return debugNetIf.Recieve()
}
