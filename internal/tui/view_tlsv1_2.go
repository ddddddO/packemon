package tui

import (
	"github.com/ddddddO/packemon"
	"github.com/rivo/tview"
)

type TLSv1_2_CLIENT_HELLO struct {
	*packemon.TLSClientHello
}

func (*TLSv1_2_CLIENT_HELLO) rows() int {
	return 8
}

func (*TLSv1_2_CLIENT_HELLO) columns() int {
	return 30
}

func (t *TLSv1_2_CLIENT_HELLO) viewTable() *tview.Table {
	table := tview.NewTable().SetBorders(false)
	table.Box = tview.NewBox().SetBorder(true).SetTitle(" TLSv1.2 Header ").SetTitleAlign(tview.AlignLeft).SetBorderPadding(1, 1, 1, 1)

	table.SetCell(0, 0, tableCellTitle("Record Layer"))
	table.SetCell(0, 1, tableCellContent("%x", t.RecordLayer.ContentType))

	// table.SetCell(1, 0, tableCellTitle("Dst Port"))
	// table.SetCell(1, 1, tableCellContent("%x (%d)", u.DstPort, u.DstPort))

	// table.SetCell(2, 0, tableCellTitle("Length"))
	// table.SetCell(2, 1, tableCellContent("%x", u.Length))

	// table.SetCell(3, 0, tableCellTitle("Checksum"))
	// table.SetCell(3, 1, tableCellContent("%x", u.Checksum))

	return table
}

type TLSv1_2_SERVER_HELLO struct {
	*packemon.TLSServerHello
}

func (*TLSv1_2_SERVER_HELLO) rows() int {
	return 8
}

func (*TLSv1_2_SERVER_HELLO) columns() int {
	return 30
}

func (t *TLSv1_2_SERVER_HELLO) viewTable() *tview.Table {
	table := tview.NewTable().SetBorders(false)
	table.Box = tview.NewBox().SetBorder(true).SetTitle(" TLSv1.2 Header ").SetTitleAlign(tview.AlignLeft).SetBorderPadding(1, 1, 1, 1)

	table.SetCell(0, 0, tableCellTitle("Server Hello"))
	table.SetCell(0, 1, tableCellContent("%x", t.ServerHello.Bytes()))

	table.SetCell(1, 0, tableCellTitle("Certificate"))
	table.SetCell(1, 1, tableCellContent("%x", t.Certificate.Bytes()))

	table.SetCell(2, 0, tableCellTitle("Server Hello Done"))
	table.SetCell(2, 1, tableCellContent("%x", t.ServerHelloDone.Bytes()))

	return table
}

type TLSv1_2_ClientKeyExchange struct {
	*packemon.TLSClientKeyExchange
}

func (*TLSv1_2_ClientKeyExchange) rows() int {
	return 8
}

func (*TLSv1_2_ClientKeyExchange) columns() int {
	return 30
}

func (t *TLSv1_2_ClientKeyExchange) viewTable() *tview.Table {
	table := tview.NewTable().SetBorders(false)
	table.Box = tview.NewBox().SetBorder(true).SetTitle(" TLSv1.2 Header ").SetTitleAlign(tview.AlignLeft).SetBorderPadding(1, 1, 1, 1)

	table.SetCell(0, 0, tableCellTitle("Client Key eXchange"))
	table.SetCell(0, 1, tableCellContent("%x", t.ClientKeyExchange.Bytes()))

	table.SetCell(1, 0, tableCellTitle("Change Chiper Spec Protocol"))
	table.SetCell(1, 1, tableCellContent("%x", t.ChangeCipherSpecProtocol.Bytes()))

	table.SetCell(2, 0, tableCellTitle("Encrypted Handshake Message"))
	table.SetCell(2, 1, tableCellContent("%x", t.EncryptedHandshakeMessage))

	return table
}

type TLSv1_2_ChangeCipherSpecAndEncryptedHandshakeMessage struct {
	*packemon.TLSChangeCipherSpecAndEncryptedHandshakeMessage
}

func (*TLSv1_2_ChangeCipherSpecAndEncryptedHandshakeMessage) rows() int {
	return 8
}

func (*TLSv1_2_ChangeCipherSpecAndEncryptedHandshakeMessage) columns() int {
	return 30
}

func (t *TLSv1_2_ChangeCipherSpecAndEncryptedHandshakeMessage) viewTable() *tview.Table {
	table := tview.NewTable().SetBorders(false)
	table.Box = tview.NewBox().SetBorder(true).SetTitle(" TLSv1.2 Header ").SetTitleAlign(tview.AlignLeft).SetBorderPadding(1, 1, 1, 1)

	table.SetCell(0, 0, tableCellTitle("Change Chiper Spec Protocol"))
	table.SetCell(0, 1, tableCellContent("%x", t.ChangeCipherSpecProtocol.Bytes()))

	table.SetCell(1, 0, tableCellTitle("Encrypted Handshake Message"))
	table.SetCell(1, 1, tableCellContent("%x", t.EncryptedHandshakeMessage.Bytes()))

	return table
}

type TLSv1_2_ApplicationData struct {
	*packemon.TLSApplicationData
}

func (*TLSv1_2_ApplicationData) rows() int {
	return 8
}

func (*TLSv1_2_ApplicationData) columns() int {
	return 30
}

func (t *TLSv1_2_ApplicationData) viewTable() *tview.Table {
	table := tview.NewTable().SetBorders(false)
	table.Box = tview.NewBox().SetBorder(true).SetTitle(" TLSv1.2 Header ").SetTitleAlign(tview.AlignLeft).SetBorderPadding(1, 1, 1, 1)

	table.SetCell(0, 0, tableCellTitle("Content Type"))
	table.SetCell(0, 1, tableCellContent("%x", t.RecordLayer.ContentType))

	table.SetCell(1, 0, tableCellTitle("Version"))
	table.SetCell(1, 1, tableCellContent("%x", t.RecordLayer.Version))

	table.SetCell(2, 0, tableCellTitle("Length"))
	table.SetCell(2, 1, tableCellContent("%x", t.RecordLayer.Length))

	table.SetCell(3, 0, tableCellTitle("Encrypted Application Data"))
	table.SetCell(3, 1, tableCellContent("%x", t.EncryptedApplicationData))

	return table
}

type TLSv1_2_EncryptedAlert struct {
	*packemon.TLSEncryptedAlert
}

func (*TLSv1_2_EncryptedAlert) rows() int {
	return 8
}

func (*TLSv1_2_EncryptedAlert) columns() int {
	return 30
}

func (t *TLSv1_2_EncryptedAlert) viewTable() *tview.Table {
	table := tview.NewTable().SetBorders(false)
	table.Box = tview.NewBox().SetBorder(true).SetTitle(" TLSv1.2 Header ").SetTitleAlign(tview.AlignLeft).SetBorderPadding(1, 1, 1, 1)

	table.SetCell(0, 0, tableCellTitle("Content Type"))
	table.SetCell(0, 1, tableCellContent("%x", t.RecordLayer.ContentType))

	table.SetCell(1, 0, tableCellTitle("Version"))
	table.SetCell(1, 1, tableCellContent("%x", t.RecordLayer.Version))

	table.SetCell(2, 0, tableCellTitle("Length"))
	table.SetCell(2, 1, tableCellContent("%x", t.RecordLayer.Length))

	table.SetCell(3, 0, tableCellTitle("Alert Message"))
	table.SetCell(3, 1, tableCellContent("%x", t.AlertMessage))

	return table
}
