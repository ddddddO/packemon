#!/bin/bash
set -e

echo "=== ネットワークラボのクリーンアップを開始します ==="

# 名前空間の削除
for ns in r1 r2 ns1 ns2 ns3 ns4 ns5 ns6; do
    sudo ip netns del "$ns" 2>/dev/null || true
done

# ブリッジの削除（これに伴い接続された veth も自動削除されます）
for br in br1 br2; do
    sudo ip link set "$br" down 2>/dev/null || true
    sudo ip link del "$br" type bridge 2>/dev/null || true
done

# ホストの bridge-nf-call 設定をデフォルト値 (1) に復元
if sudo sysctl net.bridge.bridge-nf-call-iptables &>/dev/null; then
    echo "-> net.bridge.bridge-nf-call-iptables / ip6tables をデフォルト値 (1) に復元します。"
    sudo sysctl -w net.bridge.bridge-nf-call-iptables=1 >/dev/null
    sudo sysctl -w net.bridge.bridge-nf-call-ip6tables=1 >/dev/null
fi

echo "=== クリーンアップが完了しました ==="