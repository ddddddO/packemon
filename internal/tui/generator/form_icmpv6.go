package generator

import "github.com/rivo/tview"

const (
	SELECTABLE_FORM_ICMPv6_ECHO_REQUEST_ECHO_REPLY = "ICMPv6 EchoRequest/EchoReply"
	SELECTABLE_FORM_ICMPv6_NEIGHBOR_SOLICITATION   = "ICMPv6 Neighbor Solicitation"
	SELECTABLE_FORM_ICMPv6_NEIGHBOR_ADVERTISEMENT  = "ICMPv6 Neighbor Advertisement"
	SELECTABLE_FORM_ICMPv6_ROUTER_SOLICITATION     = "ICMPv6 Router Solicitation"
	SELECTABLE_FORM_ICMPv6_ROUTER_ADVERTISEMENT    = "ICMPv6 Router Advertisement"
	SELECTABLE_FORM_ICMPv6_REDIRECT                = "ICMPv6 Redirect"
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
	icmpv6NeighborSolicitationButton := wrapSwitchButton("Neighbor Solicitation", SELECTABLE_FORM_ICMPv6_NEIGHBOR_SOLICITATION)
	icmpv6NeighborAdvertisementButton := wrapSwitchButton("Neighbor Advertisement", SELECTABLE_FORM_ICMPv6_NEIGHBOR_ADVERTISEMENT)
	icmpv6RouterSolicitationButton := wrapSwitchButton("Router Solicitation", SELECTABLE_FORM_ICMPv6_ROUTER_SOLICITATION)
	icmpv6RouterAdvertisement := wrapSwitchButton("Router Advertisement", SELECTABLE_FORM_ICMPv6_ROUTER_ADVERTISEMENT)
	icmpv6Redirect := wrapSwitchButton("Redirect", SELECTABLE_FORM_ICMPv6_REDIRECT)
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
		AddItem(icmpv6NeighborSolicitationButton, 1, 1, false).
		AddItem(tview.NewTextView(), 1, 1, false).
		AddItem(icmpv6NeighborAdvertisementButton, 1, 1, false).
		AddItem(tview.NewTextView(), 1, 1, false).
		AddItem(icmpv6RouterSolicitationButton, 1, 1, false).
		AddItem(tview.NewTextView(), 1, 1, false).
		AddItem(icmpv6RouterAdvertisement, 1, 1, false).
		AddItem(tview.NewTextView(), 1, 1, false).
		AddItem(icmpv6Redirect, 1, 1, false).
		AddItem(tview.NewTextView(), 1, 1, false).
		AddItem(quit, 1, 1, false)

	mainLayout := tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(form, 4, 1, false).
		AddItem(buttonLayout, 0, 1, true)

	return mainLayout
}
