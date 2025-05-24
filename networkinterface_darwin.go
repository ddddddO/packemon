//go:build darwin
// +build darwin

package packemon

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
)

type NetworkInterface struct {
	Intf     *net.Interface
	Handle   *pcap.Handle
	IPAddr   uint32
	IPv6Addr net.IP
	MacAddr  net.HardwareAddr

	PassiveCh chan *Passive
}

func newNetworkInterface(nwInterface string) (*NetworkInterface, error) {
	intf, err := getInterface(nwInterface)
	if err != nil {
		return nil, err
	}

	ipAddrs, err := intf.Addrs()
	if err != nil {
		return nil, err
	}

	var ipAddr uint32
	var ipv6Addr net.IP
	for _, addr := range ipAddrs {
		ipnet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}

		if ip4 := ipnet.IP.To4(); ip4 != nil {
			ipAddr = binary.BigEndian.Uint32(ip4)
		} else if ipnet.IP.To16() != nil && ipAddr == 0 {
			ipv6Addr = ipnet.IP
		}
	}

	if ipAddr == 0 && ipv6Addr == nil {
		return nil, errors.New("no IP address found for interface")
	}

	handle, err := pcap.OpenLive(intf.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("failed to open pcap handle: %v", err)
	}

	nwif := &NetworkInterface{
		Intf:      intf,
		Handle:    handle,
		IPAddr:    ipAddr,
		IPv6Addr:  ipv6Addr,
		MacAddr:   intf.HardwareAddr,
		PassiveCh: make(chan *Passive, 100),
	}

	return nwif, nil
}

func getInterface(nwInterface string) (*net.Interface, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, intf := range ifs {
		if intf.Name == nwInterface || strings.Contains(intf.Name, nwInterface) {
			return &intf, nil
		}
	}

	return nil, fmt.Errorf("interface %s not found", nwInterface)
}

func (nw *NetworkInterface) send(ethernetFrame *EthernetFrame) error {
	if err := nw.Handle.WritePacketData(ethernetFrame.Bytes()); err != nil {
		return fmt.Errorf("failed to WritePacketData: %w", err)
	}
	return nil
}

func (nw *NetworkInterface) recieve(ctx context.Context) error {
	packetSource := gopacket.NewPacketSource(nw.Handle, layers.LayerTypeEthernet)
	packets := packetSource.Packets()

	for {
		select {
		case <-ctx.Done():
			return nil
		case packet := <-packets:
			if packet == nil {
				continue
			}

			received := packet.Data()
			if len(received) < 14 { // Minimum Ethernet frame size
				continue
			}

			nw.PassiveCh <- ParsedPacket(received)
		}
	}
}

func (nw *NetworkInterface) close() error {
	if nw.Handle != nil {
		nw.Handle.Close()
	}
	return nil
}

// TODO: 以降消せないか検討
type NetworkInterfaceForTCP struct{}

var errNotSupportOnMac = fmt.Errorf("not support on mac")

func NewNetworkInterfaceForTCP(nwInterface string) (*NetworkInterfaceForTCP, error) {
	return nil, errNotSupportOnMac
}

func (nwt *NetworkInterfaceForTCP) Connect(dstIPAddr []byte, dstPort uint16) error {
	return errNotSupportOnMac
}

func (nwt *NetworkInterfaceForTCP) Write(tcpPayload []byte) (int, error) {
	return 0, errNotSupportOnMac
}

func (nwt *NetworkInterfaceForTCP) Read(buf []byte) (int, error) {
	return 0, errNotSupportOnMac
}

func (nwt *NetworkInterfaceForTCP) Close() error {
	return errNotSupportOnMac
}
