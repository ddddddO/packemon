package generator

import "github.com/rivo/tview"

const (
	SELECTABLE_FORM_ICMPv6_ECHO_REQUEST_ECHO_REPLY = "ICMPv6 EchoRequest/EchoReply"
	SELECTABLE_FORM_ICMPv6_NEIGHBOR_DISCOVERY      = "ICMPv6 Neighbor Discovery"
)

func (g *generator) icmpv6SelectPage() *tview.Flex {
	form := tview.NewForm().
		AddTextView("ICMPv6 select page", "", 60, 3, true, false)

	wrapSwitchButton := func(label string, protocol string) tview.Primitive {
		btn := tview.NewButton(label).
			SetSelectedFunc(func() {
				g.switchToProtocolPage("L4", protocol)
			})
		btnWidth := len(label) + 2

		return tview.NewFlex().
			SetDirection(tview.FlexColumn).
			AddItem(tview.NewBox(), 4, 0, false).
			AddItem(btn, btnWidth, 0, false).
			AddItem(tview.NewBox(), 0, 1, false)
	}

	icmpv6EchoButton := wrapSwitchButton("Echo Request / Echo Reply", SELECTABLE_FORM_ICMPv6_ECHO_REQUEST_ECHO_REPLY)
	icmpv6NeighborDiscoveryButton := wrapSwitchButton("Neighbor Solicitation / Neighbor Advertisement / Router Solicitation", SELECTABLE_FORM_ICMPv6_NEIGHBOR_DISCOVERY)
	quit := tview.NewFlex().
		SetDirection(tview.FlexColumn).
		AddItem(tview.NewBox(), 4, 0, false).
		AddItem(tview.NewButton("Quit").
			SetSelectedFunc(func() {
				g.app.Stop()
			}), len("Quit"), 0, false).
		AddItem(tview.NewBox(), 0, 1, false)

	buttonLayout := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(icmpv6EchoButton, 1, 1, false).
		AddItem(tview.NewTextView(), 1, 1, false).
		AddItem(icmpv6NeighborDiscoveryButton, 1, 1, false).
		AddItem(tview.NewTextView(), 1, 1, false).
		AddItem(quit, 1, 1, false)

	mainLayout := tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(form, 4, 1, false).
		AddItem(buttonLayout, 0, 1, true)

	return mainLayout
}
