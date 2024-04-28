package main

import (
	"encoding/binary"
	"fmt"
	"strconv"

	"github.com/rivo/tview"
)

// gridの中にForm二つは出力できて、一つ目のFormには入力できたけど、二つ目に遷移できなかった
func form(sendFn func([6]byte, [6]byte, uint16) error) error {
	var etherType uint16
	dst := make([]byte, 6)
	src := make([]byte, 6)

	app := tview.NewApplication()
	form := tview.NewForm().
		AddTextView("Ethernet Header", "This section generates the Ethernet header.\nIt is still under development.", 60, 4, true, false).
		AddInputField("Destination Mac Addr(hex. e.g.0xffffffffffff)", "", 14, func(textToCheck string, lastChar rune) bool {
			if len(textToCheck) < 14 {
				return true
			} else if len(textToCheck) > 14 {
				return false
			}

			b, err := strHexToBytes(textToCheck)
			if err != nil {
				return false
			}
			dst = b

			return true
		}, nil).
		AddInputField("Source Mac Addr(hex. e.g.0xffffffffffff)", "", 14, func(textToCheck string, lastChar rune) bool {
			if len(textToCheck) < 14 {
				return true
			} else if len(textToCheck) > 14 {
				return false
			}

			b, err := strHexToBytes(textToCheck)
			if err != nil {
				return false
			}
			src = b

			return true
		}, nil).
		AddDropDown("Ether Type", []string{"IPv4", "ARP"}, 1, func(selected string, _ int) {
			switch selected {
			case "IPv4":
				etherType = ETHER_TYPE_IPv4
			case "ARP":
				etherType = ETHER_TYPE_ARP
			}
		}).
		// AddInputField("Last name", "", 20, nil, nil).
		// AddTextArea("Address", "", 40, 0, 0, nil).
		// AddTextView("Notes", "This is just a demo.\nYou can enter whatever you wish.", 40, 2, true, false).
		// AddCheckbox("Age 18+", false, nil).
		// AddPasswordField("Password", "", 10, '*', nil).
		AddButton("Send!", func() {
			if err := sendFn([6]byte(dst), [6]byte(src), etherType); err != nil {
				app.Stop()
			}
		}).
		AddButton("Quit", func() {
			app.Stop()
		})
	form.SetBorder(true).SetTitle(" Make & Send packet ").SetTitleAlign(tview.AlignLeft)

	if err := app.SetRoot(form, true).EnableMouse(true).Run(); err != nil {
		return err
	}

	fmt.Println("end selected!", etherType)
	fmt.Println(dst)
	fmt.Println(src)

	return nil
}

func strHexToBytes(s string) ([]byte, error) {
	n, err := strconv.ParseUint(s, 0, 48)
	if err != nil {
		return nil, err
	}

	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, n)
	return buf[2:], nil
}
