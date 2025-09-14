package generator

import (
	"context"

	"github.com/ddddddO/packemon"
)

func (s *sender) sendL2(ctx context.Context) error {
	return s.sendFn(&packemon.EthernetFrame{
		Header: s.packets.ethernet,
	})
}
