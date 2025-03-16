package tui

import (
	"fmt"

	"github.com/ddddddO/packemon"
	"github.com/rivo/tview"
)

type TLSv1_3_SERVER_HELLO struct {
	*packemon.TLSServerHelloFor1_3
}

func (*TLSv1_3_SERVER_HELLO) rows() int {
	return 8
}

func (*TLSv1_3_SERVER_HELLO) columns() int {
	return 30
}

func (t *TLSv1_3_SERVER_HELLO) viewTable() *tview.Table {
	table := tview.NewTable().SetBorders(false)
	table.Box = tview.NewBox().SetBorder(true).SetTitle(" TLS Header ").SetTitleAlign(tview.AlignLeft).SetBorderPadding(1, 1, 1, 1)

	table.SetCell(0, 0, tableCellTitle("Record Layer - Content Type"))
	table.SetCell(0, 1, tableCellContent("%x", t.ServerHello.RecordLayer.ContentType))

	table.SetCell(1, 0, tableCellTitle("Record Layer - Version"))
	table.SetCell(1, 1, tableCellContent("%x", t.ServerHello.RecordLayer.Version))

	table.SetCell(2, 0, tableCellTitle("Record Layer - Length"))
	table.SetCell(2, 1, tableCellContent("%x", t.ServerHello.RecordLayer.Length))

	table.SetCell(3, 0, tableCellTitle("Handshake Protocol - Server Hello - Handshake Type"))
	table.SetCell(3, 1, tableCellContent("%x", t.ServerHello.HandshakeProtocol.HandshakeType))

	table.SetCell(4, 0, tableCellTitle("Handshake Protocol - Server Hello - Length"))
	table.SetCell(4, 1, tableCellContent("%x", t.ServerHello.HandshakeProtocol.Length))

	table.SetCell(5, 0, tableCellTitle("Handshake Protocol - Server Hello - Version"))
	table.SetCell(5, 1, tableCellContent("%x", t.ServerHello.HandshakeProtocol.Version))

	table.SetCell(6, 0, tableCellTitle("Handshake Protocol - Server Hello - Random"))
	table.SetCell(6, 1, tableCellContent("%x", t.ServerHello.HandshakeProtocol.Random))

	table.SetCell(7, 0, tableCellTitle("Handshake Protocol - Server Hello - Session ID Length"))
	table.SetCell(7, 1, tableCellContent("%x", t.ServerHello.HandshakeProtocol.SessionIDLength))

	table.SetCell(8, 0, tableCellTitle("Handshake Protocol - Server Hello - Session ID"))
	table.SetCell(8, 1, tableCellContent("%x", t.ServerHello.HandshakeProtocol.SessionID))

	table.SetCell(9, 0, tableCellTitle("Handshake Protocol - Server Hello - Cipher Suite"))
	table.SetCell(9, 1, tableCellContent("%x", t.ServerHello.HandshakeProtocol.CipherSuites))

	table.SetCell(10, 0, tableCellTitle("Handshake Protocol - Server Hello - Comression Method"))
	table.SetCell(10, 1, tableCellContent("%x", t.ServerHello.HandshakeProtocol.CompressionMethods))

	next := 11
	if t.ServerHello.HandshakeProtocol.ExtensionsLength != nil {
		table.SetCell(next, 0, tableCellTitle("Handshake Protocol - Server Hello - Extensions Length"))
		table.SetCell(next, 1, tableCellContent("%x", t.ServerHello.HandshakeProtocol.ExtensionsLength))
		next++
	}

	for i, e := range t.ServerHello.HandshakeProtocol.Extentions {
		table.SetCell(next, 0, tableCellTitle(fmt.Sprintf("Handshake Protocol - Server Hello - Extensions %d - Type:", i)))
		table.SetCell(next, 1, tableCellContent("%x", e.Type))

		table.SetCell(next+1, 0, tableCellTitle(fmt.Sprintf("Handshake Protocol - Server Hello - Extensions %d - Length:", i)))
		table.SetCell(next+1, 1, tableCellContent("%x", e.Length))

		table.SetCell(next+2, 0, tableCellTitle(fmt.Sprintf("Handshake Protocol - Server Hello - Extensions %d - Data:", i)))
		table.SetCell(next+2, 1, tableCellContent("%x", e.Data))

		next += 3
	}

	table.SetCell(next, 0, tableCellTitle("Change Cipher Spec - Content Type"))
	table.SetCell(next, 1, tableCellContent("%x", t.ChangeCipherSpecProtocol.RecordLayer.ContentType))
	next++

	table.SetCell(next, 0, tableCellTitle("Change Cipher Spec - Version"))
	table.SetCell(next, 1, tableCellContent("%x", t.ChangeCipherSpecProtocol.RecordLayer.Version))
	next++

	table.SetCell(next, 0, tableCellTitle("Change Cipher Spec - Length"))
	table.SetCell(next, 1, tableCellContent("%x", t.ChangeCipherSpecProtocol.RecordLayer.Length))
	next++

	table.SetCell(next, 0, tableCellTitle("Change Cipher Spec - Change Cipher Spec Message"))
	table.SetCell(next, 1, tableCellContent("%x", t.ChangeCipherSpecProtocol.ChangeCipherSpecMessage))
	next++

	for i, applicationDataProtocol := range t.ApplicationDataProtocols {
		table.SetCell(next, 0, tableCellTitle(fmt.Sprintf("Application Data - %d - Opaque Type", i)))
		table.SetCell(next, 1, tableCellContent("%x", applicationDataProtocol.RecordLayer.ContentType))

		table.SetCell(next+1, 0, tableCellTitle(fmt.Sprintf("Application Data - %d - Version", i)))
		table.SetCell(next+1, 1, tableCellContent("%x", applicationDataProtocol.RecordLayer.Version))

		table.SetCell(next+2, 0, tableCellTitle(fmt.Sprintf("Application Data - %d - Length", i)))
		table.SetCell(next+2, 1, tableCellContent("%x", applicationDataProtocol.RecordLayer.Length))

		table.SetCell(next+3, 0, tableCellTitle(fmt.Sprintf("Application Data - %d - Encrypted Application Data", i)))
		table.SetCell(next+3, 1, tableCellContent("%x", applicationDataProtocol.EncryptedApplicationData))

		next += 4
	}

	return table
}
