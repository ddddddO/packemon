package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/ddddddO/packemon"
	ec "github.com/ddddddO/packemon/egress_control"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"golang.org/x/net/websocket"
)

const DEFAULT_TARGET_NW_INTERFACE = "eth0"

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
			os.Exit(1)
		}
		defer ec.Close(ebpfProg, qdisc)
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
	e.Static("/", "public")
	e.GET("/ws", handleWebSocket(netIf.PassiveCh))
	e.Logger.Fatal(e.Start(":8081"))

	return nil
}

// https://zenn.dev/empenguin/articles/bcf95c19451020 参考
func handleWebSocket(passiveCh chan *packemon.Passive) func(c echo.Context) error {
	return func(c echo.Context) error {
		websocket.Handler(func(ws *websocket.Conn) {
			defer ws.Close()

			// 初回のメッセージを送信
			err := websocket.Message.Send(ws, "Connected to Packemon server!")
			if err != nil {
				c.Logger().Error(err)
			}

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
					err := websocket.Message.Send(ws, fmt.Sprintf("Server: \"%s\" received!", p.HighLayerProto()))
					if err != nil {
						c.Logger().Error(err)
					}
				}
			}
		}).ServeHTTP(c.Response(), c.Request())
		return nil
	}
}
