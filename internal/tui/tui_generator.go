package tui

import (
	"context"

	"github.com/ddddddO/packemon"
	"github.com/rivo/tview"
)

type generator struct {
	networkInterface *packemon.NetworkInterface
	sendFn           func(*packemon.EthernetFrame) error

	app *tview.Application

	grid   *tview.Grid
	pages  *tview.Pages
	list   *tview.List
	sender *sender
}

func NewGenerator(networkInterface *packemon.NetworkInterface) *generator {
	pages := tview.NewPages()
	grid := tview.NewGrid()
	grid.Box = tview.NewBox().SetTitle(TITLE_GENERATOR).SetBorder(true)
	list := tview.NewList()
	list.SetTitle("Protocols").SetBorder(true)

	return &generator{
		networkInterface: networkInterface,
		sendFn:           networkInterface.Send,

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
	g.pages.AddPage("ERROR", errView(err, g.app), true, true)
}
