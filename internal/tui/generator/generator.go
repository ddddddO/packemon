package generator

import (
	"context"

	"github.com/cilium/ebpf"
	"github.com/ddddddO/packemon"
	"github.com/ddddddO/packemon/internal/tui"
	"github.com/rivo/tview"
)

type generator struct {
	networkInterface *packemon.NetworkInterface
	analyzer         *analyzer
	sendFn           func(*packemon.EthernetFrame) error

	app *tview.Application

	grid   *tview.Grid
	pages  *tview.Pages
	list   *tview.List
	sender *sender
}

func New(networkInterface *packemon.NetworkInterface, ingressMap *ebpf.Map, egressMap *ebpf.Map) *generator {
	pages := tview.NewPages()
	grid := tview.NewGrid()
	grid.Box = tview.NewBox().SetTitle(tui.TITLE_GENERATOR).SetBorder(true)
	list := tview.NewList()
	list.SetTitle("Protocols").SetBorder(true)

	return &generator{
		networkInterface: networkInterface,
		analyzer: &analyzer{
			ingress: ingressMap,
			egress:  egressMap,
		},
		sendFn: networkInterface.Send,

		app:   tview.NewApplication(),
		grid:  grid,
		pages: pages,
		list:  list,
	}
}

func (g *generator) Run(ctx context.Context) error {
	if err := g.form(ctx, g.sendFn); err != nil {
		return err
	}
	return g.app.SetRoot(g.grid, true).EnableMouse(true).SetFocus(g.grid).Run()
}

func (g *generator) addErrPage(err error) {
	g.pages.AddPage("ERROR", tui.ErrView(err, g.app), true, true)
}
