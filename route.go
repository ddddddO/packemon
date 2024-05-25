package packemon

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

func GetDefaultRouteMAC() (string, error) {
	// TODO: せっかくだし出来ればpackamonのNewNetworkInterface, ARP 使ってmacアドレス取得したい。送信前に受信するとこを起動してARPのみ取得するようにする必要がある
	// nwi, err := NewNetworkInterface(senderNWInterface)
	// if err != nil {
	// 	return "", err
	// }

	defaultRouteIP, err := GetDefaultRouteIP()
	if err != nil {
		return "", err
	}

	stdout, err := ExecIPNeigh()
	if err != nil {
		return "", err
	}

	lines := strings.Split(stdout, "\n")
	for i := range lines {
		// lladdr = Link Layer Address
		if !(strings.Contains(lines[i], defaultRouteIP) && strings.Contains(lines[i], "lladdr")) {
			continue
		}

		split := strings.Split(lines[i], " ")
		if len(split) >= 5 {
			if split[3] == "lladdr" {
				return split[4], nil // e.g. 00:15:5d:fb:bf:3a
			}
		}
	}

	return "", errors.New("could not obtain MAC address for default route")
}

func GetDefaultRouteIP() (string, error) {
	stdout, err := ExecIPRoute()
	if err != nil {
		return "", err
	}

	// e.g. lines = [default via 172.23.240.1 dev eth0 proto kernel  172.17.0.0/16 dev docker0 proto kernel scope link src 172.17.0.1 linkdown  172.23.240.0/20 dev eth0 proto kernel scope link src 172.23.242.78  ]
	lines := strings.Split(stdout, "\n")
	for i := range lines {
		if !strings.Contains(lines[i], "default") {
			continue
		}

		split := strings.Split(lines[i], " ")
		if len(split) >= 2 {
			return split[2], nil // e.g. 172.23.240.1
		}
	}

	return "", errors.New("could not obtain IP address for default route")
}

func ExecIPRoute() (string, error) {
	// $ ip route
	// default via 172.23.240.1 dev eth0 proto kernel
	// 172.17.0.0/16 dev docker0 proto kernel scope link src 172.17.0.1 linkdown
	// 172.23.240.0/20 dev eth0 proto kernel scope link src 172.23.242.78
	return ExecIP("route")
}

func ExecIPNeigh() (string, error) {
	// $ ip neigh
	// 172.23.240.1 dev eth0 lladdr 00:15:5d:fb:bf:3a REACHABLE
	// 192.168.10.110 dev docker0  FAILED
	// 172.23.242.79 dev eth0  FAILED
	return ExecIP("neigh")
}

const COMMAND_IP = "ip"

// const COMMAND_ARP = "arp" // ipコマンド(ip neigh)へ移行進んでるみたいでarp入ってないマシンあるみたい

func ExecIP(args ...string) (string, error) {
	return ExecCommand(COMMAND_IP, args...)
}

func ExecCommand(command string, args ...string) (string, error) {
	binPath, err := exec.LookPath(command)
	if err != nil {
		return "", err
	}

	bufStdout := &bytes.Buffer{}
	bufStderr := &bytes.Buffer{}
	cmd := exec.Command(binPath, args...)
	cmd.Stdout = bufStdout
	cmd.Stderr = bufStderr

	if err := cmd.Run(); err != nil {
		// 例えば存在しないサブコマンド指定で実行すると、stderrに吐かれてる. 以下は「ip routes」の実行結果
		// e.g. exit status 1. details: Object "routes" is unknown, try "ip help".
		msg := fmt.Sprintf("%s. details: %s", err, bufStderr)
		return "", errors.New(msg)
	}

	return bufStdout.String(), nil
}
