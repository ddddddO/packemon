# NOTE: only developer
# /github.com/ddddddO/packemon/egress_control/ 配下で以下を実行しeBPFコード生成
# go generate

# いかな感じで単発で送信
debug:
	sudo go run cmd/packemon/main.go --send --proto icmp --debug

test:
	go test -v

credit:
	gocredits . > CREDITS
