# いかな感じで単発で送信
debug:
	sudo go run cmd/packemon/main.go --send --proto icmp --debug

test:
	go test -v
