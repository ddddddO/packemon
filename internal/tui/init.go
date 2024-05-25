package tui

import (
	"fmt"
	"strings"

	"github.com/ddddddO/packemon"
)

func init() {
	DEFAULT_MAC_DESTINATION = "0x00155dfbbf3a"
	defaultRouteMAC, err := packemon.GetDefaultRouteMAC()
	if err == nil {
		DEFAULT_MAC_DESTINATION = fmt.Sprintf("0x%s", strings.ReplaceAll(defaultRouteMAC, ":", ""))
	}

	DEFAULT_ARP_TARGET_IP = "192.168.10.110"
	defaultRouteIP, err := packemon.GetDefaultRouteIP()
	if err == nil {
		DEFAULT_ARP_TARGET_IP = defaultRouteIP
	}

	DEFAULT_IP_DESTINATION = "192.168.10.110" // raspbbery pi
}
