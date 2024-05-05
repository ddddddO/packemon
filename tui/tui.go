package tui

import (
	"github.com/ddddddO/packemon"
	"github.com/rivo/tview"
)

type tui struct {
	app   *tview.Application
	grid  *tview.Grid
	pages *tview.Pages
	list  *tview.List
}

func NewTUI(wantSend bool) *tui {
	app := tview.NewApplication()

	if wantSend {
		pages := tview.NewPages()

		list := tview.NewList().
			AddItem("ICMP", "", '1', func() {
				pages.SwitchToPage("ICMP")
				app.SetFocus(pages)
			}).
			AddItem("IPv4", "", '2', func() {
				pages.SwitchToPage("IPv4")
				app.SetFocus(pages)
			}).
			AddItem("ARP", "", '3', func() {
				pages.SwitchToPage("ARP")
				app.SetFocus(pages)
			}).
			AddItem("Ethernet", "", '4', func() {
				pages.SwitchToPage("Ethernet")
				app.SetFocus(pages)
			})

		grid := tview.NewGrid().
			SetRows(3, 0, 3).
			SetColumns(30, 0, 30).
			SetBorders(true)
		grid.Box = tview.NewBox().SetBorder(true).SetTitle(" Packemon <Generator> ")

		// Layout for screens narrower than 100 cells (menu and side bar are hidden).
		grid.AddItem(list, 0, 0, 0, 0, 0, 0, true).
			AddItem(pages, 1, 0, 1, 3, 0, 0, false)
			// AddItem(sideBar, 0, 0, 0, 0, 0, 0, false)

		// Layout for screens wider than 100 cells.
		grid.AddItem(list, 1, 0, 1, 1, 0, 100, true).
			AddItem(pages, 1, 1, 1, 1, 0, 100, false)
			// AddItem(sideBar, 1, 2, 1, 1, 0, 100, false)

		return &tui{
			app:   app,
			grid:  grid,
			pages: pages,
			list:  list,
		}
	}

	grid := tview.NewGrid()
	grid.Box = tview.NewBox().SetBorder(true).SetTitle(" Packemon <Monitor> ")
	return &tui{
		app:  tview.NewApplication(),
		grid: grid,
	}
}

func (t *tui) Monitor(passiveCh chan packemon.Passive) error {
	go t.updateView(passiveCh)
	return t.app.SetRoot(t.grid, true).Run()
}

func (t *tui) Generator(sendFn func(*packemon.EthernetFrame) error) error {
	if err := t.form(sendFn); err != nil {
		return err
	}
	// return t.app.SetRoot(t.pages, true).EnableMouse(true).Run()
	return t.app.SetRoot(t.grid, true).SetFocus(t.grid).Run()
}
