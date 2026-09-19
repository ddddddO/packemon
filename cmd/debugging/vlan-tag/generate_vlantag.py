#!/usr/bin/python3

from scapy.all import Ether, Dot1Q, IP, ICMP, sendp

# 1. L2 (Ethernetヘッダ)
# dst: 宛先MACアドレス, src: 送信元MACアドレス
eth_layer = Ether(dst="ff:ff:ff:ff:ff:ff", src="aa:bb:cc:dd:ee:ff")

# 2. VLANタグ (Dot1Qヘッダ)
# vlan=10: VLAN ID 10を指定
vlan_layer = Dot1Q(vlan=10)

# 3. L3 (IPヘッダ)
# src: 送信元IP, dst: 宛先IP
ip_layer = IP(src="192.168.10.100", dst="192.168.10.1")

# 4. L4 (ICMPヘッダ)
icmp_layer = ICMP()

# フレームを結合: L2 / VLAN / L3 / L4 の順
packet = eth_layer / vlan_layer / ip_layer / icmp_layer

# 物理インターフェース(eth0)からパケットを送信
sendp(packet, iface="eth0")
print("生成されたパケットの概要:", packet.summary())
