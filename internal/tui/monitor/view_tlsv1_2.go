package monitor

import (
	"fmt"

	"github.com/ddddddO/packemon"
	"github.com/ddddddO/packemon/internal/tui"
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
	table.Box = tview.NewBox().SetBorder(true).SetTitle(" TLS Header ").SetTitleAlign(tview.AlignLeft).SetBorderPadding(1, 1, 1, 1)

	table.SetCell(0, 0, tui.TableCellTitle("Record Layer - Content Type"))
	table.SetCell(0, 1, tui.TableCellContent("%x", t.RecordLayer.ContentType))

	table.SetCell(1, 0, tui.TableCellTitle("Record Layer - Version"))
	table.SetCell(1, 1, tui.TableCellContent("%x", t.RecordLayer.Version))

	table.SetCell(2, 0, tui.TableCellTitle("Record Layer - Length"))
	table.SetCell(2, 1, tui.TableCellContent("%x", t.RecordLayer.Length))

	table.SetCell(3, 0, tui.TableCellTitle("Handshake Protocol - Client Hello - Handshake Type"))
	table.SetCell(3, 1, tui.TableCellContent("%x", t.HandshakeProtocol.HandshakeType))

	table.SetCell(4, 0, tui.TableCellTitle("Handshake Protocol - Client Hello - Length"))
	table.SetCell(4, 1, tui.TableCellContent("%x", t.HandshakeProtocol.Length))

	table.SetCell(5, 0, tui.TableCellTitle("Handshake Protocol - Client Hello - Version"))
	table.SetCell(5, 1, tui.TableCellContent("%x", t.HandshakeProtocol.Version))

	table.SetCell(6, 0, tui.TableCellTitle("Handshake Protocol - Client Hello - Random"))
	table.SetCell(6, 1, tui.TableCellContent("%x", t.HandshakeProtocol.Random))

	table.SetCell(7, 0, tui.TableCellTitle("Handshake Protocol - Client Hello - Session ID Length"))
	table.SetCell(7, 1, tui.TableCellContent("%x", t.HandshakeProtocol.SessionIDLength))

	table.SetCell(8, 0, tui.TableCellTitle("Handshake Protocol - Client Hello - Session ID"))
	table.SetCell(8, 1, tui.TableCellContent("%x", t.HandshakeProtocol.SessionID))

	table.SetCell(9, 0, tui.TableCellTitle("Handshake Protocol - Client Hello - Cipher Suites Length"))
	table.SetCell(9, 1, tui.TableCellContent("%x", t.HandshakeProtocol.CipherSuitesLength))

	table.SetCell(10, 0, tui.TableCellTitle("Handshake Protocol - Client Hello - Cipher Suites"))
	table.SetCell(10, 1, tui.TableCellContent("%x", t.HandshakeProtocol.CipherSuites))

	table.SetCell(11, 0, tui.TableCellTitle("Handshake Protocol - Client Hello - Compression Methods Length"))
	table.SetCell(11, 1, tui.TableCellContent("%x", t.HandshakeProtocol.CompressionMethodsLength))

	table.SetCell(12, 0, tui.TableCellTitle("Handshake Protocol - Client Hello - Compression Methods"))
	table.SetCell(12, 1, tui.TableCellContent("%x", t.HandshakeProtocol.CompressionMethods))

	next := 13
	if t.HandshakeProtocol.ExtensionsLength != nil {
		table.SetCell(next, 0, tui.TableCellTitle("Handshake Protocol - Client Hello - Extensions Length"))
		table.SetCell(next, 1, tui.TableCellContent("%x", t.HandshakeProtocol.ExtensionsLength))
		next++
	}

	for i, e := range t.HandshakeProtocol.Extentions {
		table.SetCell(next, 0, tui.TableCellTitle(fmt.Sprintf("Handshake Protocol - Client Hello - Extensions %d - Type:", i)))
		table.SetCell(next, 1, tui.TableCellContent("%x", e.Type))

		table.SetCell(next+1, 0, tui.TableCellTitle(fmt.Sprintf("Handshake Protocol - Client Hello - Extensions %d - Length:", i)))
		table.SetCell(next+1, 1, tui.TableCellContent("%x", e.Length))

		table.SetCell(next+2, 0, tui.TableCellTitle(fmt.Sprintf("Handshake Protocol - Client Hello - Extensions %d - Data:", i)))
		table.SetCell(next+2, 1, tui.TableCellContent("%x", e.Data))

		next += 3
	}

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
	table.Box = tview.NewBox().SetBorder(true).SetTitle(" TLS Header ").SetTitleAlign(tview.AlignLeft).SetBorderPadding(1, 1, 1, 1)

	table.SetCell(0, 0, tui.TableCellTitle("Record Layer - Content Type"))
	table.SetCell(0, 1, tui.TableCellContent("%x", t.ServerHello.RecordLayer.ContentType))

	table.SetCell(1, 0, tui.TableCellTitle("Record Layer - Version"))
	table.SetCell(1, 1, tui.TableCellContent("%x", t.ServerHello.RecordLayer.Version))

	table.SetCell(2, 0, tui.TableCellTitle("Record Layer - Length"))
	table.SetCell(2, 1, tui.TableCellContent("%x", t.ServerHello.RecordLayer.Length))

	table.SetCell(3, 0, tui.TableCellTitle("Handshake Protocol - Server Hello - Handshake Type"))
	table.SetCell(3, 1, tui.TableCellContent("%x", t.ServerHello.HandshakeProtocol.HandshakeType))

	table.SetCell(4, 0, tui.TableCellTitle("Handshake Protocol - Server Hello - Length"))
	table.SetCell(4, 1, tui.TableCellContent("%x", t.ServerHello.HandshakeProtocol.Length))

	table.SetCell(5, 0, tui.TableCellTitle("Handshake Protocol - Server Hello - Version"))
	table.SetCell(5, 1, tui.TableCellContent("%x", t.ServerHello.HandshakeProtocol.Version))

	table.SetCell(6, 0, tui.TableCellTitle("Handshake Protocol - Server Hello - Random"))
	table.SetCell(6, 1, tui.TableCellContent("%x", t.ServerHello.HandshakeProtocol.Random))

	table.SetCell(7, 0, tui.TableCellTitle("Handshake Protocol - Server Hello - Session ID Length"))
	table.SetCell(7, 1, tui.TableCellContent("%x", t.ServerHello.HandshakeProtocol.SessionIDLength))

	table.SetCell(8, 0, tui.TableCellTitle("Handshake Protocol - Server Hello - Session ID"))
	table.SetCell(8, 1, tui.TableCellContent("%x", t.ServerHello.HandshakeProtocol.SessionID))

	table.SetCell(9, 0, tui.TableCellTitle("Handshake Protocol - Server Hello - Cipher Suite"))
	table.SetCell(9, 1, tui.TableCellContent("%x", t.ServerHello.HandshakeProtocol.CipherSuites))

	table.SetCell(10, 0, tui.TableCellTitle("Handshake Protocol - Server Hello - Comression Method"))
	table.SetCell(10, 1, tui.TableCellContent("%x", t.ServerHello.HandshakeProtocol.CompressionMethods))

	next := 11
	if t.ServerHello.HandshakeProtocol.ExtensionsLength != nil {
		table.SetCell(next, 0, tui.TableCellTitle("Handshake Protocol - Server Hello - Extensions Length"))
		table.SetCell(next, 1, tui.TableCellContent("%x", t.ServerHello.HandshakeProtocol.ExtensionsLength))
		next++
	}

	for i, e := range t.ServerHello.HandshakeProtocol.Extentions {
		table.SetCell(next, 0, tui.TableCellTitle(fmt.Sprintf("Handshake Protocol - Server Hello - Extensions %d - Type:", i)))
		table.SetCell(next, 1, tui.TableCellContent("%x", e.Type))

		table.SetCell(next+1, 0, tui.TableCellTitle(fmt.Sprintf("Handshake Protocol - Server Hello - Extensions %d - Length:", i)))
		table.SetCell(next+1, 1, tui.TableCellContent("%x", e.Length))

		table.SetCell(next+2, 0, tui.TableCellTitle(fmt.Sprintf("Handshake Protocol - Server Hello - Extensions %d - Data:", i)))
		table.SetCell(next+2, 1, tui.TableCellContent("%x", e.Data))

		next += 3
	}

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
	table.Box = tview.NewBox().SetBorder(true).SetTitle(" TLS Header ").SetTitleAlign(tview.AlignLeft).SetBorderPadding(1, 1, 1, 1)

	table.SetCell(0, 0, tui.TableCellTitle("Client Key eXchange"))
	table.SetCell(0, 1, tui.TableCellContent("%x", t.ClientKeyExchange.Bytes()))

	table.SetCell(1, 0, tui.TableCellTitle("Change Chiper Spec Protocol"))
	table.SetCell(1, 1, tui.TableCellContent("%x", t.ChangeCipherSpecProtocol.Bytes()))

	table.SetCell(2, 0, tui.TableCellTitle("Encrypted Handshake Message"))
	table.SetCell(2, 1, tui.TableCellContent("%x", t.EncryptedHandshakeMessage))

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
	table.Box = tview.NewBox().SetBorder(true).SetTitle(" TLS Header ").SetTitleAlign(tview.AlignLeft).SetBorderPadding(1, 1, 1, 1)

	table.SetCell(0, 0, tui.TableCellTitle("Change Chiper Spec Protocol"))
	table.SetCell(0, 1, tui.TableCellContent("%x", t.ChangeCipherSpecProtocol.Bytes()))

	table.SetCell(1, 0, tui.TableCellTitle("Encrypted Handshake Message"))
	table.SetCell(1, 1, tui.TableCellContent("%x", t.EncryptedHandshakeMessage.Bytes()))

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
	table.Box = tview.NewBox().SetBorder(true).SetTitle(" TLS Header ").SetTitleAlign(tview.AlignLeft).SetBorderPadding(1, 1, 1, 1)

	table.SetCell(0, 0, tui.TableCellTitle("Content Type"))
	table.SetCell(0, 1, tui.TableCellContent("%x", t.RecordLayer.ContentType))

	table.SetCell(1, 0, tui.TableCellTitle("Version"))
	table.SetCell(1, 1, tui.TableCellContent("%x", t.RecordLayer.Version))

	table.SetCell(2, 0, tui.TableCellTitle("Length"))
	table.SetCell(2, 1, tui.TableCellContent("%x", t.RecordLayer.Length))

	table.SetCell(3, 0, tui.TableCellTitle("Encrypted Application Data"))
	table.SetCell(3, 1, tui.TableCellContent("%x", t.EncryptedApplicationData))

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
	table.Box = tview.NewBox().SetBorder(true).SetTitle(" TLS Header ").SetTitleAlign(tview.AlignLeft).SetBorderPadding(1, 1, 1, 1)

	table.SetCell(0, 0, tui.TableCellTitle("Content Type"))
	table.SetCell(0, 1, tui.TableCellContent("%x", t.RecordLayer.ContentType))

	table.SetCell(1, 0, tui.TableCellTitle("Version"))
	table.SetCell(1, 1, tui.TableCellContent("%x", t.RecordLayer.Version))

	table.SetCell(2, 0, tui.TableCellTitle("Length"))
	table.SetCell(2, 1, tui.TableCellContent("%x", t.RecordLayer.Length))

	table.SetCell(3, 0, tui.TableCellTitle("Alert Message"))
	table.SetCell(3, 1, tui.TableCellContent("%x", t.AlertMessage))

	return table
}
