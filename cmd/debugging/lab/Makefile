.PHONY: setup cleanup setup-ipv6 exec packemon help

# デフォルト設定
ns ?= ns1
cmd ?= ip addr
args ?= monitor

# ns1〜ns6 の場合は veth-nsX をデフォルトのインターフェースにする
ifeq ($(filter ns%,$(ns)),$(ns))
interface ?= veth-$(ns)
else
interface ?= veth-r1-br1
endif

help:
	@echo "利用可能なターゲット:"
	@echo "  make setup                - 環境をクリーンアップした上で、通常のネットワークラボを構築する"
	@echo "  make setup-ipv6           - 環境をクリーンアップした上で、IPv6有効化ラボを構築する"
	@echo "  make cleanup              - ラボ環境を完全にクリーンアップする"
	@echo "  make exec ns=ns1 cmd=...  - 指定した名前空間（ns1〜ns6, r1, r2）で任意のコマンドを実行する"
	@echo "  make packemon ns=ns1      - 指定した名前空間で packemon を実行する（自動で --interface が付与されます）"
	@echo ""
	@echo "【利用例 (exec)】"
	@echo "  # 同一セグメント内の通信"
	@echo "  make exec ns=ns1 cmd='ping -c 2 192.168.1.20'"
	@echo ""
	@echo "  # 別ルータ（別セグメント）をまたいだ通信 (ns1 -> ns4)"
	@echo "  make exec ns=ns1 cmd='ping -c 3 192.168.2.10'"
	@echo "  make exec ns=ns1 cmd='ping6 -c 3 fd00:2::10'  # (IPv6有効時)"
	@echo ""
	@echo "【利用例 (packemon)】"
	@echo "  make packemon ns=ns1                          # 自動で --interface veth-ns1 が適用されます"
	@echo "  make packemon ns=ns1 args='generator'         # ジェネレーター機能を使う場合"
	@echo "  make packemon ns=r1 interface=veth-r1-br1     # ルータなど別のインタフェースを指定する場合"

setup: cleanup
	@sudo ./setup-netlab.sh

setup-ipv6: cleanup
	@sudo ./setup-netlab.sh --enable-ipv6

cleanup:
	@sudo ./cleanup-netlab.sh

exec:
	@sudo ip netns exec $(ns) $(cmd)

packemon:
	@sudo ip netns exec $(ns) go run ../../../cmd/packemon/*.go $(args) --interface $(interface)