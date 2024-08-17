package main

import (
	"fmt"
	"log"
	"net"
)

// https://haydz.github.io/2020/07/06/Go-Windows-NIC.html
// Windows 対応諦めようか、gopacket package 使えたとしてもホスト側で install しないといけないものありそうで、それはあんまりやりたくない
func main() {
	log.Println("Windows!")

	interfaces, err := net.Interfaces()
	if err != nil {
		panic(err)
	}

	for i := range interfaces {
		intf := interfaces[i]
		fmt.Printf("\t%v, Name: %s\n", intf, intf.Name)
	}
	// Output:
	// {11 1500 イーサネット b8:20:8e:7a:f3:88 broadcast|multicast}, Name: イーサネット
	// {10 1500 ローカル エリア接続* 1 58:6d:67:be:6d:fc broadcast|multicast}, Name: ローカル エリア接続* 1
	// {9 1500 ローカル エリア接続* 2 5a:6d:67:be:6d:fb broadcast|multicast}, Name: ローカル エリア接続* 2
	// {17 1430 携帯電話 00:a0:c6:00:00:01 0}, Name: 携帯電話
	// {14 1500 Wi-Fi 58:6d:67:be:6d:fb up|broadcast|multicast|running}, Name: Wi-Fi
	// {8 1500 Bluetooth ネットワーク接続 58:6d:67:be:6d:ff broadcast|multicast}, Name: Bluetooth ネットワーク接続
	// {1 -1 Loopback Pseudo-Interface 1  up|loopback|multicast|running}, Name: Loopback Pseudo-Interface 1
	// {65 1500 vEthernet (WSL (Hyper-V firewall)) 00:15:5d:63:01:f9 up|broadcast|multicast|running}, Name: vEthernet (WSL (Hyper-V firewall))

	log.Println("end")
}
