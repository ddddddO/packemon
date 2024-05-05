# Packémon

Packet monster, or `Packémon` for short! (っ‘-’)╮=͟͟͞͞◒ ヽ( '-'ヽ)）<br>

TUI tool and Go library for monitoring packets on specific network interfaces and sending packets of arbitrary input.


- 開発途上で気長にやる予定
- 現在の機能は以下（WIP）
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

## 動作確認

### パケットキャプチャ
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

### 手軽にブロードキャスト
```console
$ arping -c 1 1.2.3.4
ARPING 1.2.3.4 from 172.23.242.78 eth0
Sent 1 probes (1 broadcast(s))
Received 0 response(s)
```


## 動作確認の様子
- Ethernetフレームのみ作って送信（`77c9149` でコミットしたファイルにて）

  ![](./doc/Frame.png)

- ARPリクエストを作って送信（`390f266` でコミットしたファイルにて。中身はめちゃくちゃと思うけど）

  ![](./doc/ARP.png)

- ARPリクエストを受信してパース（`b6a025a` でコミット）

  ![](./doc/ARP_request_console.png)
  ![](./doc/ARP_request.png)

## 参考
- 「Golangで作るソフトウェアルータ」
  - その実装コード: https://github.com/sat0ken/go-curo
- https://terassyi.net/posts/2020/03/29/ethernet.html
- 動作確認用コマンドの参考
  - https://zenn.dev/takai404/articles/76d47e944d8e18
- [Scrapboxメモ書き](https://scrapbox.io/ddddddo/%E3%83%8D%E3%83%83%E3%83%88%E3%83%AF%E3%83%BC%E3%82%AF%E7%B3%BB%E8%AA%AD%E3%81%BF%E7%89%A9)
