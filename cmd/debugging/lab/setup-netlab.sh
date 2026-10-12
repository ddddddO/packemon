#!/bin/bash
set -e

# ==============================================================================
# 【ネットワーク構成イメージ (完全ローカル・クリーン版)】
#
#   [ ルータ: r1 ] ────────────── (veth: 10.0.0.1/30 & fd00:0:0:1::1/64) ────────────── [ ルータ: r2 ]
#  (IPv4: 192.168.1.1)                                                                (IPv4: 192.168.2.1)
#  (IPv6: fd00:1::1)                                                                  (IPv6: fd00:2::1)
#       │                                                                            │
#  [ スイッチ: br1 ]                                                           [ スイッチ: br2 ]
#   ├── [ ns1 ] (IPv4: 192.168.1.10 / IPv6: fd00:1::10)                         ├── [ ns4 ] (IPv4: 192.168.2.10 / IPv6: fd00:2::10)
#   ├── [ ns2 ] (IPv4: 192.168.1.20 / IPv6: fd00:1::20)                         ├── [ ns5 ] (IPv4: 192.168.2.20 / IPv6: fd00:2::20)
#   └── [ ns3 ] (IPv4: 192.168.1.30 / IPv6: fd00:1::30)                         └── [ ns6 ] (IPv4: 192.168.2.30 / IPv6: fd00:2::30)
# ==============================================================================

ENABLE_IPV6=${ENABLE_IPV6:-false}
for arg in "$@"; do
    if [ "$arg" = "--enable-ipv6" ]; then
        ENABLE_IPV6=true
    fi
done

echo "=== ネットワーク環境の構築を開始します (完全ローカル版 / IPv6有効化: $ENABLE_IPV6) ==="

echo "=== 1. ルータおよびホスト用の名前空間作成 ==="
for ns in r1 r2 ns1 ns2 ns3 ns4 ns5 ns6; do
    sudo ip netns add "$ns"
done

echo "=== 2. 各ルータ配下の L2 スイッチ（ブリッジ）の作成 ==="
for br in br1 br2; do
    sudo ip link add name "$br" type bridge
    sudo ip link set "$br" up
done

echo "=== 3. ルータ間の接続ケーブル作成 ==="
sudo ip link add veth-r1-r2 type veth peer name veth-r2-r1
sudo ip link set veth-r1-r2 netns r1
sudo ip link set veth-r2-r1 netns r2

sudo ip netns exec r1 ip addr add 10.0.0.1/30 dev veth-r1-r2
if [ "$ENABLE_IPV6" = "true" ]; then
    sudo ip netns exec r1 ip -6 addr add fd00:0:0:1::1/64 dev veth-r1-r2
fi
sudo ip netns exec r1 ip link set veth-r1-r2 up
sudo ip netns exec r1 ip link set lo up

sudo ip netns exec r2 ip addr add 10.0.0.2/30 dev veth-r2-r1
if [ "$ENABLE_IPV6" = "true" ]; then
    sudo ip netns exec r2 ip -6 addr add fd00:0:0:1::2/64 dev veth-r2-r1
fi
sudo ip netns exec r2 ip link set veth-r2-r1 up
sudo ip netns exec r2 ip link set lo up

echo "=== 4. r1 とスイッチ (br1) の接続 ==="
sudo ip link add veth-r1-br1 type veth peer name veth-br1-r1
sudo ip link set veth-r1-br1 netns r1
sudo ip link set veth-br1-r1 up
sudo ip link set veth-br1-r1 master br1

sudo ip netns exec r1 ip addr add 192.168.1.1/24 dev veth-r1-br1
if [ "$ENABLE_IPV6" = "true" ]; then
    sudo ip netns exec r1 ip -6 addr add fd00:1::1/64 dev veth-r1-br1
fi
sudo ip netns exec r1 ip link set veth-r1-br1 up

echo "=== 5. r2 とスイッチ (br2) の接続 ==="
sudo ip link add veth-r2-br2 type veth peer name veth-br2-r2
sudo ip link set veth-r2-br2 netns r2
sudo ip link set veth-br2-r2 up
sudo ip link set veth-br2-r2 master br2

sudo ip netns exec r2 ip addr add 192.168.2.1/24 dev veth-r2-br2
if [ "$ENABLE_IPV6" = "true" ]; then
    sudo ip netns exec r2 ip -6 addr add fd00:2::1/64 dev veth-r2-br2
fi
sudo ip netns exec r2 ip link set veth-r2-br2 up

echo "=== 6. br1 側ホスト (ns1, ns2, ns3) の接続とアドレス設定 ==="
for i in 1 2 3; do
    sudo ip link add veth-ns$i type veth peer name veth-br1-$i
    sudo ip link set veth-ns$i netns ns$i

    sudo ip netns exec ns$i ip addr add 192.168.1.$((i*10))/24 dev veth-ns$i
    sudo ip netns exec ns$i ip link set veth-ns$i up
    sudo ip netns exec ns$i ip link set lo up
    sudo ip netns exec ns$i ip route add default via 192.168.1.1

    if [ "$ENABLE_IPV6" = "true" ]; then
        sudo ip netns exec ns$i ip -6 addr add fd00:1::$((i*10))/64 dev veth-ns$i
        sudo ip netns exec ns$i ip -6 route add default via fd00:1::1
    fi

    sudo ip link set veth-br1-$i up
    sudo ip link set veth-br1-$i master br1
done

echo "=== 7. br2 側ホスト (ns4, ns5, ns6) の接続とアドレス設定 ==="
for i in 4 5 6; do
    idx=$((i-3))
    sudo ip link add veth-ns$i type veth peer name veth-br2-$idx
    sudo ip link set veth-ns$i netns ns$i

    sudo ip netns exec ns$i ip addr add 192.168.2.$((idx*10))/24 dev veth-ns$i
    sudo ip netns exec ns$i ip link set veth-ns$i up
    sudo ip netns exec ns$i ip link set lo up
    sudo ip netns exec ns$i ip route add default via 192.168.2.1

    if [ "$ENABLE_IPV6" = "true" ]; then
        sudo ip netns exec ns$i ip -6 addr add fd00:2::$((idx*10))/64 dev veth-ns$i
        sudo ip netns exec ns$i ip -6 route add default via fd00:2::1
    fi

    sudo ip link set veth-br2-$idx up
    sudo ip link set veth-br2-$idx master br2
done

echo "=== 8. ルータ間の静的ルーティング設定 ==="
sudo ip netns exec r1 ip route add 192.168.2.0/24 via 10.0.0.2
sudo ip netns exec r2 ip route add 192.168.1.0/24 via 10.0.0.1

if [ "$ENABLE_IPV6" = "true" ]; then
    sudo ip netns exec r1 ip -6 route add fd00:2::/64 via fd00:0:0:1::2
    sudo ip netns exec r2 ip -6 route add fd00:1::/64 via fd00:0:0:1::1
fi

echo "=== 9. ルータのIPフォワーディングの有効化 ==="
for ns in r1 r2; do
    sudo ip netns exec $ns sysctl -w net.ipv4.ip_forward=1 >/dev/null
    sudo ip netns exec $ns sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null
done

echo "=== 10. WSL mirrored環境対策（bridge-nf-call の無効化） ==="
if sudo sysctl net.bridge.bridge-nf-call-iptables &>/dev/null; then
    echo "-> bridge-nf-call-iptables / ip6tables を 0 に設定します。"
    sudo sysctl -w net.bridge.bridge-nf-call-iptables=0 >/dev/null
    sudo sysctl -w net.bridge.bridge-nf-call-ip6tables=0 >/dev/null
fi

echo "=== すべての完全ローカルネットワーク構築が完了しました！ ==="