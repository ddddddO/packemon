package monitor

import (
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

type header struct {
	Title string
	Color tcell.Color
}

func (h header) cell() *tview.TableCell {
	return tview.NewTableCell(h.Title).
		SetTextColor(h.Color).
		SetAttributes(tcell.AttrBold).
		SetSelectable(false).
		SetAlign(tview.AlignCenter)
}

var headers = map[rune]header{
	'd': {Title: "DstMAC", Color: tcell.Color38},
	's': {Title: "SrcMAC", Color: tcell.Color48},
	't': {Title: "Type", Color: tcell.Color98},
	'p': {Title: "Proto", Color: tcell.Color50},
	'D': {Title: "DstIP", Color: tcell.Color51},
	'S': {Title: "SrcIP", Color: tcell.Color181},
	'i': {Title: "Info", Color: tcell.ColorWhite},
}

func (m *monitor) setHeader() {
	m.table.SetFixed(1, 0)
	m.table.SetCell(0, 0, header{Title: "ID", Color: tcell.ColorWhite}.cell())

	x := 1
	for _, column := range m.columns {
		header, ok := headers[column]
		if !ok {
			continue
		}
		m.table.SetCell(0, x, header.cell())
		x++
	}
}
