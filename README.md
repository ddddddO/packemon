# Packémon

Packet monster, or `Packémon` for short! (っ‘-’)╮=͟͟͞͞◒ ヽ( '-'ヽ) <br>

TUI tool and Go library for sending packets of arbitrary input and monitoring packets on specific network interface (`eth0`). **This tool is not available for Windows and MacOS.**<br>

I intend to develop it patiently🌴

## Feature

This TUI tool has two major functions: packet generation and packet monitoring.

### Packet Generator

![](./doc/tui_overview_generator.png)

- [ ] Send generated packets to any network interface.
  - Currently, it can be sent only to specific network interface(`eth0`).

- The following types of packets are covered.
  - [x] Ethernet
  - [x] ARP
  - [ ] IPv4 (WIP)
  - [ ] ICMP (WIP)
  - [ ] TCP (WIP)
  - [ ] UDP (WIP)
  - [ ] DNS (WIP)
  - [ ] HTTP (WIP)
  - [ ] xxxxx....

### Packet Monitor

![](./doc/tui_overview_monitor.png)

- [ ] Monitor any network interface.
  - Currently, only certain network interface (`eth0`) can be monitored.

- The following types of packets are covered.
  - [x] Ethernet header
  - [x] ARP header
  - [x] IPv4 header
  - [ ] xxxxx....

## Installation

```console
$ go install github.com/ddddddO/packemon/cmd/packemon
```

## Usage

- Packet Monitor
  ```console
  $ sudo packemon
  ```

- Packet Generator
  ```console
  $ sudo packemon --send
  ```

## Related tools
- netcat
- [Nmap](https://nmap.org/)

## Acknowledgment
- [rivo/tview](https://github.com/rivo/tview)
  - Packemon is using this TUI library.

- [Golangで作るソフトウェアルータ](https://booth.pm/ja/items/5290391)
  - The way Go handles syscalls, packet checksum logic, etc. was helpful. This is a book in Japanese.


## Links
- 「Golangで作るソフトウェアルータ」
  - その実装コード: https://github.com/sat0ken/go-curo
- https://terassyi.net/posts/2020/03/29/ethernet.html
- 動作確認用コマンドの参考
  - https://zenn.dev/takai404/articles/76d47e944d8e18
- [Scrapboxメモ書き](https://scrapbox.io/ddddddo/%E3%83%8D%E3%83%83%E3%83%88%E3%83%AF%E3%83%BC%E3%82%AF%E7%B3%BB%E8%AA%AD%E3%81%BF%E7%89%A9)

## Log (japanese)

<details><summary>xxx</summary>

- WSL2のDebianで動作した。

- 任意の Ethernet ヘッダ / IPv4 ヘッダ / ARP / ICMP を楽に作れてフレームを送信できる
- 以下はtmuxで3分割した画面に各種ヘッダのフォーム画面を表示している。そして ICMP echo request を送信し、 echo reply が返ってきていることを Wireshark で確認した様子
  ![](./doc/tui_ether_ip_icmp.png)
  ![](./doc/tui_send_icmp_result1.png)
  ![](./doc/tui_send_icmp_result2.png)

- フレームを受信して詳細表示（ARPとIPv4）
  ![](./doc/tui_send_recieve.png)

  <details><summary>少し前のUI（`5062561` のコミット）</summary>

  ![](./doc/tui_0428.png)
  ![](./doc/tui_cap_0428.png)

  </details>

- TUIライブラリとして https://github.com/rivo/tview を使わせてもらってる🙇

### 動作確認

#### パケットキャプチャ
```console
$ sudo tcpdump -U -i eth0 -w - | /mnt/c/Program\ Files/Wireshark/Wireshark.exe -k -i -
```

- 受信画面

  ```console
  $ sudo go run cmd/packemon/main.go
  ```


- 送信画面

  ```console
  $ sudo go run cmd/packemon/main.go --send
  ```

- 単発フレーム送信コマンド（e.g. ARP request）

  ```console
  $ sudo go run cmd/packemon/main.go --send --proto arp
  ```

#### 手軽にブロードキャスト
```console
$ arping -c 1 1.2.3.4
ARPING 1.2.3.4 from 172.23.242.78 eth0
Sent 1 probes (1 broadcast(s))
Received 0 response(s)
```


### 動作確認の様子

<details><summary>xxx</summary>

- Ethernetフレームのみ作って送信（`77c9149` でコミットしたファイルにて）

  ![](./doc/Frame.png)

- ARPリクエストを作って送信（`390f266` でコミットしたファイルにて。中身はめちゃくちゃと思うけど）

  ![](./doc/ARP.png)

- ARPリクエストを受信してパース（`b6a025a` でコミット）

  ![](./doc/ARP_request_console.png)
  ![](./doc/ARP_request.png)

</details>
