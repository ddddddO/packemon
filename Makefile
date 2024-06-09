# cmd/packemon/ 配下で以下
# go generate
# sudo go run .

# いかな感じで単発で送信
debug:
	sudo go run cmd/packemon/main.go --send --proto icmp --debug

test:
	go test -v
