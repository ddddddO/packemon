package tui

import (
	"fmt"
	"strings"

	"github.com/ddddddO/packemon"
)

type filter struct {
	value string // Monitor の Filter 入力欄の文字列
}

func newFilter() *filter {
	return &filter{}
}

func (f *filter) contains(passive *packemon.Passive) bool {
	// filter 文字列が空ならすべて表示
	if len(strings.TrimSpace(f.value)) == 0 {
		return true
	}

	if passive.EthernetFrame != nil {
		if f.con(fmt.Sprintf("%x", passive.EthernetFrame.Header.Dst)) {
			return true
		}
		if f.con(fmt.Sprintf("%x", passive.EthernetFrame.Header.Src)) {
			return true
		}
		if f.con(fmt.Sprintf("%x", passive.EthernetFrame.Header.Typ)) {
			return true
		}
	}

	if passive.IPv4 != nil {
		if f.con(passive.IPv4.StrSrcIPAddr()) {
			return true
		}
		if f.con(passive.IPv4.StrDstIPAddr()) {
			return true
		}
	}

	if passive.IPv6 != nil {
		if f.con(passive.IPv6.StrSrcIPAddr()) {
			return true
		}
		if f.con(passive.IPv6.StrDstIPAddr()) {
			return true
		}
	}

	if f.con(passive.HighLayerProto()) {
		return true
	}

	return false
}

func (f *filter) con(target string) bool {
	return strings.Contains(target, f.value)
}
