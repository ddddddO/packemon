### BGP の環境を tinet で構築(tmux実行しておく)
以下でインストールした tinet コマンドを利用
```console
curl -Lo /usr/bin/tinet https://github.com/tinynetwork/tinet/releases/download/v0.0.3/tinet.linux_amd64
chmod +x /usr/bin/tinet
tinet --version
```

```console
# 以下の順で、BGP の通信を pcap に取れる環境を作成
$ make up
$ make login
# 以下のみコンテナ内で実行
$ tcpdump -i net0 -s 0 -w /home/ddddddO/packemon/cmd/debugging/bgp/pcap/$(date "+%Y%m%d_%H%M").pcap port 179
$ make conf
# BGP の設定と daemon が動くので少し待つ。その後、CTL+C で tcpdump を止める

# 環境削除
$ make down
```

`/home/ddddddO/packemon/cmd/debugging/bgp/pcap/$(date "+%Y%m%d_%H%M").pcap` のファイルを Wireshark に読み込む

```console

# 以下の順で、packemon で BGP の実装を進める
$ cd ~/github.com/ddddddO/packemon/cmd/debugging/bgp
$ (go ファイル編集)
$ go build
$ make login
# BGP daemon を止める
$ /etc/init.d/frr stop
# パケットをキャプチャ
$ tcpdump -i net0 -s 0 -w /home/ddddddO/packemon/cmd/debugging/bgp/pcap/$(date "+%Y%m%d_%H%M").pcap port 179

# 別セッションのコンテナ内で
$ make login
$ cd /home/ddddddO/packemon/cmd/debugging/bgp
$ ./bgp
# パケットキャプチャを止めて Wireshark で読み込んでデバッグを進める
```

- tinet で構築した BGP Router 同士のパケットの様子
  - [env_tinet.pcap](./pcap/env_tinet.pcap)
  - ![](./pcap/env_tinet.png)
- tinet で構築後、上の手順で片方は packemon の bgp 用プログラムで実行(`172.17.0.4`)した様子
  - [succeeded_bgp.pcap](./pcap/succeeded_bgp.pcap)
  - ![](./pcap/succeeded_bgp.png)
  - 現状、Open ~ Keepalive ~ Update ~ Notification が送信できるようになった

### 作業ログ
#### [この手順](https://github.com/ddddddO/packemon/issues/68#issuecomment-2408943662)で、ピア同士で BGP の通信ができた様子

![](./succeeded_peering_bgp.png)
![](./bgp.pcap.png)


### 参考
- https://milestone-of-se.nesuke.com/nw-advanced/bgp/bgp-sequence-message-format/
    - BGP のシーケンスと BGP の pcap ファイルあり
