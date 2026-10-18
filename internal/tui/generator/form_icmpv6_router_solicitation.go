package generator

import (
	"context"

	"github.com/ddddddO/packemon"
	"github.com/rivo/tview"
)

var checkedCalcICMPv6RouterSolicitationChecksum = true

func (g *generator) icmpv6RouterSolicitationForm() *tview.Form {
	var assembler packemon.Assembler = &packemon.ScratchICMPv6RouterSolicitationAssembler{}
	icmpForm, collectValues := buildDynamicForm(assembler, "ICMPv6", "This section generates ICMPv6 Router Solicitation messages.", nil)

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
		checkedCalcICMPv6RouterSolicitationChecksum = calc
		g.sender.packets.icmpv6RouterSolicitation = packemon.ParsedICMPv6RouterSolicitation(b)
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
