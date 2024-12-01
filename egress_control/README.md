- 外部パッケージの github.com/vishvananda/netlink が何らか利用できない状態になって、RST パケットがドロップできないとなっても、回避策はある（[ref](https://zenn.dev/satoken/articles/golang-rfc9401#%E5%8B%95%E4%BD%9C%E3%83%81%E3%82%A7%E3%83%83%E3%82%AF-~%E6%AD%BB%E4%BA%A1%E3%83%95%E3%83%A9%E3%82%B0%E3%81%8C%E7%AB%8B%E3%81%A3%E3%81%9Ftcp%E3%83%91%E3%82%B1%E3%83%83%E3%83%88%E3%81%A8%E3%81%AF~)）

    ```console
    $ sudo iptables -A OUTPUT -s 127.0.0.1 -d 127.0.0.1 -p tcp --tcp-flags RST RST -j DROP
    ```

- 初回 go generate 前に、以下あたりを確認しておく
  - https://ebpf-go.dev/guides/getting-started/#ebpf-c-program
  - [2. Linuxカーネルヘッダーのインストール](https://zenn.dev/ttsurumi/articles/71d25a46f3e27a#2.-linux%E3%82%AB%E3%83%BC%E3%83%8D%E3%83%AB%E3%83%98%E3%83%83%E3%83%80%E3%83%BC%E3%81%AE%E3%82%A4%E3%83%B3%E3%82%B9%E3%83%88%E3%83%BC%E3%83%AB)
    - だと、ちょっとうまくいかなかった。自分の環境が悪かったか。
  - 以下を新しいPCで初回実行で go generate できるようになった。
    ```console
    $ sudo apt search linux-headers
    # ↑の結果から↓へ指定
    $ sudo apt install linux-headers-6.1.0-21-amd64
    $ sudo ln -s /usr/include/x86_64-linux-gnu/asm /usr/include/asm
    $ cd ~/github.com/ddddddO/packemon/egress_control
    $ go generate
    ```
