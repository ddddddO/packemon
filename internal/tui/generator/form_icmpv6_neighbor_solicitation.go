package generator

import (
	"context"

	"github.com/ddddddO/packemon"
	"github.com/rivo/tview"
)

var checkedCalcICMPv6NeighborSolicitationChecksum = true

func (g *generator) icmpv6NeighborSolicitationForm() *tview.Form {
	var assembler packemon.Assembler = &packemon.ScratchICMPv6NeighborSolicitationAssembler{}
	icmpForm, collectValues := buildDynamicForm(assembler, "ICMPv6", "This section generates ICMPv6 Neighbor Solicitation messages.", map[string]string{
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
		checkedCalcICMPv6NeighborSolicitationChecksum = calc
		g.sender.packets.icmpv6NeighborSolicitation = packemon.ParsedICMPv6NeighborSolicitation(b)
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
