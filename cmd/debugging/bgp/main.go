package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/ddddddO/packemon"
	"github.com/ddddddO/packemon/internal/debugging"
	tc "github.com/ddddddO/packemon/tc_program"
)

// 現状、cmd/packemon の方で実装すると、デフォルトルートのIPアドレスを取得する時にエラーになってしまうので、このディレクトリで試す感じ
func main() {
	fmt.Println("debugging BGP")

	var nwInterface string
	flag.StringVar(&nwInterface, "interface", "net0", "Specify name of network interface to be sent/received. Default is 'eth0'.")

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
			fmt.Fprintln(os.Stderr, err)
			// error出力するが、処理は進める
			// os.Exit(1)
		}
		defer func() {
			if err := tc.Close(ebpfObjs, qdisc, filterEgress); err != nil {
				fmt.Fprintln(os.Stderr, err)
			}
		}()
	}

	netIf, err := packemon.NewNetworkInterface(nwInterface)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer netIf.Close()

	debugNetIf := debugging.NewDebugNetworkInterface(netIf)
	defer debugNetIf.Close()

	if err := debugNetIf.FlowBGP(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	fmt.Println("end")
}
