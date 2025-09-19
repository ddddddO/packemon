package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/ddddddO/packemon"
	"github.com/ddddddO/packemon/internal/debugging"
	"github.com/ddddddO/packemon/internal/tui/generator"
	"github.com/ddddddO/packemon/internal/tui/monitor"
	tc "github.com/ddddddO/packemon/tc_program"
	"github.com/urfave/cli/v3"
)

var (
	Version  = "unset"
	Revision = "unset"
)

const DEFAULT_TARGET_NW_INTERFACE = "eth0"

// d: dest mac, s: src mac, t: type, p: protocol, D: dest ip, S: src ip, i: info
const DEFAULT_MONITOR_COLUMNS = "dstpDSi"
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
	interfaceFlag := &cli.StringFlag{
		Name:  "interface",
		Usage: `Specify name of network interface to be sent/received. Default is 'eth0'. (default "eth0")`,
	}
	monitorCommand := &cli.Command{
		Name:    "monitor",
		Aliases: []string{"m", "mon"},
		Usage:   "Monitor mode. You can monitor packets received and sent on the specified interface. Default is 'eth0' interface.",
		Flags: []cli.Flag{
			interfaceFlag,
			&cli.StringFlag{
				Name:  "columns",
				Usage: `Specify columns to be displayed in monitor mode. Default is 'dstpDSi' . (default "dstpDSi")`,
			},
			&cli.IntFlag{
				Name:  "limit",
				Usage: "Limits the list of packets that can be displayed on monitor mode. Default is '1000'; if less than -1 is specified, no limit. (default 1000)",
			},
		},
		Before: notExistArgs,
		Action: actionMonitor,
	}

	app := &cli.Command{
		Name:    "packemon",
		Usage:   fmt.Sprintf("Packet monster (っ‘-’)╮=͟͟͞͞◒ ヽ( '-'ヽ) TUI tool for sending packets of arbitrary input and monitoring packets on any network interfaces (default: eth0). Windows/macOS/Linux\n%s", METAMON),
		Version: fmt.Sprintf("%s / revision %s", Version, Revision),
		// 以下でデフォルトでmonitorを起動するようにしているが、packemon --interface xxx はできないっぽい...
		DefaultCommand: monitorCommand.Name,
		Commands: []*cli.Command{
			monitorCommand,
			{
				Name:    "generator",
				Aliases: []string{"g", "gen"},
				Usage:   "Generator mode. Arbitrary packets can be generated and sent.",
				Flags:   []cli.Flag{interfaceFlag},
				Before:  notExistArgs,
				Action:  actionGenerator,
			},
			{
				Name:    "interfaces",
				Aliases: []string{"i", "intfs"},
				Usage:   "Check the list of interfaces.",
				Before:  notExistArgs,
				Action:  actionInterfaces,
			},
			{
				Name:    "debugging",
				Aliases: []string{"d", "debug"},
				Usage:   "Debugging mode.",
				Flags: []cli.Flag{
					interfaceFlag,
					&cli.StringFlag{
						Name:  "proto",
						Usage: "Specify either 'arp', 'icmp', 'tcp', 'dns' or 'http'.",
					},
					&cli.BoolFlag{
						Name:  "send",
						Usage: "Debugging for Generator",
					},
				},
				Before: notExistArgs,
				Action: actionDebugging,
			},
			{
				Name:    "version",
				Aliases: []string{"v"},
				Usage:   "Prints the version.",
				Before:  notExistArgs,
				Action: func(ctx context.Context, c *cli.Command) error {
					fmt.Printf("packemon version %s / revision %s\n", Version, Revision)
					return nil
				},
			},
		},
	}

	if err := app.Run(context.Background(), os.Args); err != nil {
		fmt.Fprint(os.Stderr, err)
	}
}

func notExistArgs(ctx context.Context, c *cli.Command) (context.Context, error) {
	if c.NArg() != 0 {
		return nil, errors.New("command line contains unnecessary arguments")
	}
	return ctx, nil
}

func actionGenerator(ctx context.Context, c *cli.Command) error {
	nwInterface := DEFAULT_TARGET_NW_INTERFACE
	if c.String("interface") != "" {
		nwInterface = c.String("interface")
	}

	var ingressMap, egressMap *ebpf.Map
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

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	netIf, err := packemon.NewNetworkInterface(nwInterface)
	if err != nil {
		return err
	}
	defer netIf.Close()

	generator.DEFAULT_NW_INTERFACE = nwInterface
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

	packemonTUI := generator.New(netIf, ingressMap, egressMap)
	return packemonTUI.Run(ctx)
}

func actionMonitor(ctx context.Context, c *cli.Command) error {
	columns := DEFAULT_MONITOR_COLUMNS
	if c.String("columns") != "" {
		columns = c.String("columns")
	}
	for i := range columns {
		if !strings.Contains(DEFAULT_MONITOR_COLUMNS, string(columns[i])) {
			return fmt.Errorf("Contains unsupported columns: %s\n", string(columns[i]))
		}
	}

	limit := DEFAULT_MONITOR_LIMIT
	if c.Int("limit") != 0 {
		limit = c.Int("limit")
	}

	nwInterface := DEFAULT_TARGET_NW_INTERFACE
	if c.String("interface") != "" {
		nwInterface = c.String("interface")
	}
	netIf, err := packemon.NewNetworkInterface(nwInterface)
	if err != nil {
		return err
	}
	defer netIf.Close()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	packemonTUI := monitor.New(netIf, columns, limit)
	return packemonTUI.Run(ctx)
}

// TODO: テーブル形式で出力してくれるライブラリ使ってもいいかも
func actionInterfaces(ctx context.Context, c *cli.Command) error {
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

func actionDebugging(ctx context.Context, c *cli.Command) error {
	nwInterface := DEFAULT_TARGET_NW_INTERFACE
	if c.String("interface") != "" {
		nwInterface = c.String("interface")
	}
	netIf, err := packemon.NewNetworkInterface(nwInterface)
	if err != nil {
		return err
	}
	defer netIf.Close()

	if c.Bool("send") {
		// この辺り、デフォ値設定するとこももってきたけどいらんかも
		generator.DEFAULT_NW_INTERFACE = nwInterface
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

		protocol := c.String("proto")
		return debugMode(true, protocol, netIf, packemon.HardwareAddr(firsthopMACAddr))
	}

	// Monitor の debug は本チャンの networkinterface.go 使うようにする
	go netIf.Recieve(ctx)
	return debugPrint(ctx, netIf.PassiveCh)
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
