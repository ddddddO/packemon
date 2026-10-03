package generator

import (
	"context"

	"github.com/ddddddO/packemon"
	"github.com/rivo/tview"
)

var checkedCalcICMPv6Checksum = true
var checkedCalcICMPv6Timestamp = false

func (g *generator) icmpv6Form() *tview.Form {
	var assembler packemon.Assembler = &packemon.ScratchICMPv6Assembler{}
	icmpForm, collectValues := buildDynamicForm(assembler, "ICMPv6", "This section generates ICMPv6 messages.", nil)

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
		checkedCalcICMPv6Checksum = calc
		g.sender.packets.icmpv6 = packemon.ParsedICMPv6Echo(b)
		return nil
	})

	icmpForm.
		AddCheckbox("Automatically add timestamp ?", checkedCalcICMPv6Timestamp, func(checked bool) {
			checkedCalcICMPv6Timestamp = checked
		}).
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
