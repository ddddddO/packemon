- ref: https://zenn.dev/satoken/articles/golang-tls1_2#%E4%B8%8B%E6%BA%96%E5%82%99

1. このディレクトリ配下で、以下を一度実行（Raspberry Pi）
  ```console
  $ mkcert my-tls.com localhost 127.0.0.1
  ```

1. リモート上のこの配下で以下（Raspberry Pi）
  ```console
  $ go run main.go
  ```

1. Wireshark起動（WSL）
  ```console
  $ sudo tcpdump -U -i eth0 -w - | /mnt/c/Program\ Files/Wireshark/Wireshark.exe -k -i -
  ```

1. TLS1.2の通信（WSL）で、Wireshakで確認できる
  ```console
  $ echo | openssl s_client -4 -tls1_2 -cipher AES128-GCM-SHA256 -connect 192.168.10.110:10443
  ```
