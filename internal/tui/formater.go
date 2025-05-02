package tui

import (
	"fmt"
	"strings"

	"github.com/rivo/tview"
)

func TableCellTitle(title string) *tview.TableCell {
	return tview.NewTableCell(Padding(title))
}

func TableCellContent(format string, a ...any) *tview.TableCell {
	return tview.NewTableCell(Padding(fmt.Sprintf(format, a...)))
}

func Padding(s string) string {
	spaces := strings.Repeat(" ", 3)
	return fmt.Sprintf("%s%s%s", spaces, s, spaces)
}

func Spacer(bb []byte) string {
	ret := ""
	for i, b := range bb {
		ret += fmt.Sprintf("%02x ", b)

		// 8byte毎に、大きくスペースとる
		if (i+1)%8 == 0 {
			ret += "  "
		}
	}
	return ret
}
