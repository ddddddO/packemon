- ref: https://zenn.dev/satoken/articles/golang-tls1_2#%E4%B8%8B%E6%BA%96%E5%82%99

1. このディレクトリ配下で、以下を一度実行（Raspberry Pi）
    ```console
    $ mkcert my-tls.com localhost 127.0.0.1
    ```

1. リモート上のこのディレクトリ配下で以下（Raspberry Pi）
    ```console
    $ go run main.go
    ```

1. Wireshark起動（WSL）
    ```console
    $ sudo tcpdump -U -i eth0 -w - | /mnt/c/Program\ Files/Wireshark/Wireshark.exe -k -i -
    ```

    - `tcp.port == 10443` でfilter

1. TLS1.2の通信（WSL）をWireshakで確認できる
    ```console
    $ echo | openssl s_client -4 -tls1_2 -cipher AES128-GCM-SHA256 -connect 192.168.10.110:10443
    ```

1. packemon の debug mode で、TCP 3way handshake ~ TLS handshake ~ TLS Application data の送受信までを以下コマンドで確認できる
    ```console
    $ sudo go run cmd/packemon/*.go --send --debug --proto tcp-tls-handshake
    ```

    - `func SendTCP3wayAndTLShandshake` (packemon/internal/debugging/networkinterface.go) の `srcPort` を実行毎に変更すること

    - `debugging/tls-server` 実行中に出力されるログ (`CLIENT_RANDOM 000000...`) を、ローカルの適当なファイル (`C:\packemon\key.log` とか) にコピペして、Wiresharkの「編集 > 設定 > Protocols > TLS」の「(Pre)-Master-Secret log filename」にそのファイルパスを設定後に、再度上記コマンド実行で、暗号化されているメッセージが復号されて見られる
