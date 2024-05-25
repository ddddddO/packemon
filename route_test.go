package packemon_test

import (
	"testing"

	"github.com/ddddddO/packemon"
)

func Test_GetDefaultRouteIP(t *testing.T) {
	defaultRouteIP, err := packemon.GetDefaultRouteIP()
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("default route ip: %s\n", defaultRouteIP)
}

func Test_GetDefaultRouteMAC(t *testing.T) {
	defaultRouteMAC, err := packemon.GetDefaultRouteMAC()
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("default route mac: %s\n", defaultRouteMAC)
}
