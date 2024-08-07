# デバッグ環境のメモ

- `tshark` で icmp のキャプチャ

```console
pi@raspberrypi:~/github.com/ddddddO/packemon $ sudo tshark -i wlan0 -T fields -E header=y -E separator=/t -e eth.src -e ip.src -e eth.dst -e ip.dst icmp
Running as user "root" and group "root". This could be dangerous.
eth.src	ip.src	eth.dst	ip.dst
Capturing on 'wlan0'
58:6d:67:be:6d:fb	192.168.10.109	dc:a6:32:91:51:58	192.168.10.110
dc:a6:32:91:51:58	192.168.10.110	58:6d:67:be:6d:fb	192.168.10.109


```