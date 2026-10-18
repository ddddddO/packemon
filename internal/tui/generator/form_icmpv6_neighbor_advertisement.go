package generator

import (
	"context"

	"github.com/ddddddO/packemon"
	"github.com/rivo/tview"
)

var checkedCalcICMPv6NeighborAdvertisementChecksum = true

func (g *generator) icmpv6NeighborAdvertisementForm() *tview.Form {
	var assembler packemon.Assembler = &packemon.ScratchICMPv6NeighborAdvertisementAssembler{}
	icmpForm, collectValues := buildDynamicForm(assembler, "ICMPv6", "This section generates ICMPv6 Neighbor Advertisement messages.", map[string]string{
		"target_address": DEFAULT_IPv6_DESTINATION,
	})

	g.sender.registerApplyForm("ICMPv6", func() error {
		values := collectValues()
		b, err := assembler.Assemble(values, nil)
		if err != nil {
			return err
		}
		calc, err := boolFromValues(values, "calc_checksum")
		if err != nil {
			return err
		}
		checkedCalcICMPv6NeighborAdvertisementChecksum = calc
		g.sender.packets.icmpv6NeighborAdvertisement = packemon.ParsedICMPv6NeighborAdvertisement(b)
		return nil
	})

	icmpForm.
		AddButton("Send!", func() {
			if err := g.sender.sendLayer4(context.TODO()); err != nil {
				g.addErrPage(err)
			}
		}).
		AddButton("Quit", func() {
			g.app.Stop()
		})

	return icmpForm
}
