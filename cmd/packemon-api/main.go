package main

import (
	"context"
	"embed"
	"flag"
	"fmt"
	"io/fs"
	"net/http"
	"os"

	"github.com/ddddddO/packemon"
	ec "github.com/ddddddO/packemon/egress_control"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"golang.org/x/net/websocket"
)

const DEFAULT_TARGET_NW_INTERFACE = "eth0"

// ref: https://medium.com/@pavelfokin/how-to-embed-react-app-into-go-binary-12905d5963f0
// ref: https://echo.labstack.com/docs/cookbook/embed-resources#with-go-116-embed-feature
//
//go:embed web/dist
var web embed.FS

func main() {
	var nwInterface string
	flag.StringVar(&nwInterface, "interface", DEFAULT_TARGET_NW_INTERFACE, "Specify name of network interface to be sent/received. Default is 'eth0'.")
	var isClient bool
	flag.BoolVar(&isClient, "client", false, "Client of bidirectional")

	flag.Parse()

	if !isClient {
		// Generator で3way handshake する際に、カーネルが自動でRSTパケットを送ってたため、ドロップするため
		ebpfProg, qdisc, err := ec.PrepareDropingRSTPacket(nwInterface)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			// error出力するが、処理は進める
			// os.Exit(1)
		}
		defer func() {
			if err := ec.Close(ebpfProg, qdisc); err != nil {
				fmt.Fprintln(os.Stderr, err)
			}
		}()
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := run(ctx, isClient, nwInterface); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
}

func run(ctx context.Context, isClient bool, nwInterface string) error {
	if isClient {
		// TODO:
		return nil
	}

	netIf, err := packemon.NewNetworkInterface(nwInterface)
	if err != nil {
		return err
	}
	defer netIf.Close()
	go netIf.Recieve(ctx)

	e := echo.New()
	e.Use(middleware.Logger())
	e.GET("/ws", handleWebSocket(netIf.PassiveCh))

	e.GET("/*", echo.WrapHandler(handleAsset()))
	e.Logger.Fatal(e.Start(":8082"))

	return nil
}

func handleAsset() http.Handler {
	return http.FileServer(getFileSystem())
}

func getFileSystem() http.FileSystem {
	fsys, err := fs.Sub(web, "web/dist")
	if err != nil {
		panic(err)
	}
	return http.FS(fsys)
}

type PassiveJSON struct {
	DestinationMACAddr string `json:"dst_mac"`
	SourceMACAddr      string `json:"src_mac"`
	Type               string `json:"type"`
	Proto              string `json:"proto"`
	DestinationIPAddr  string `json:"dst_ip"`
	SourceIPAddr       string `json:"src_ip"`
}

// https://zenn.dev/empenguin/articles/bcf95c19451020 参考
func handleWebSocket(passiveCh chan *packemon.Passive) func(c echo.Context) error {
	return func(c echo.Context) error {
		websocket.Handler(func(ws *websocket.Conn) {
			defer ws.Close()

			c.Logger().Infof("Client IP: %s, Server IP: %s", ws.RemoteAddr().String(), ws.LocalAddr().String())

			// 初回のメッセージを送信
			// err := websocket.Message.Send(ws, "Connected to Packemon server!")
			// if err != nil {
			// 	c.Logger().Error(err)
			// }

			for {
				// Client からのメッセージを読み込む
				// msg := ""
				// err = websocket.Message.Receive(ws, &msg)
				// if err != nil {
				// 	c.Logger().Error(err)
				// }

				// Client からのメッセージを元に返すメッセージを作成し送信する
				// err := websocket.Message.Send(ws, fmt.Sprintf("Server: \"%s\" received!", msg))
				// if err != nil {
				// 	c.Logger().Error(err)
				// }

				for p := range passiveCh {
					pj := PassiveJSON{
						DestinationMACAddr: p.EthernetFrame.Header.Dst.String(),
						SourceMACAddr:      p.EthernetFrame.Header.Src.String(),
						Type:               fmt.Sprintf("%x", p.EthernetFrame.Header.Typ),
						Proto:              p.HighLayerProto(),
					}
					if p.IPv4 != nil {
						pj.DestinationIPAddr = p.IPv4.StrDstIPAddr()
						pj.SourceIPAddr = p.IPv4.StrSrcIPAddr()
					}
					if p.IPv6 != nil {
						pj.DestinationIPAddr = p.IPv6.StrDstIPAddr()
						pj.SourceIPAddr = p.IPv6.StrSrcIPAddr()
					}
					err := websocket.JSON.Send(ws, pj)
					// err := websocket.Message.Send(ws, fmt.Sprintf("Server: \"%s\" received!", p.HighLayerProto()))
					if err != nil {
						c.Logger().Error(err)
						return
					}
				}
			}
		}).ServeHTTP(c.Response(), c.Request())
		return nil
	}
}
