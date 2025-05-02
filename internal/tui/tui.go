package tui

import (
	"context"
)

const (
	TITLE_GENERATOR = " Packemon <Generator> "
	TITLE_MONITOR   = " Packemon <Monitor> "
)

type TUI interface {
	Run(context.Context) error
}
